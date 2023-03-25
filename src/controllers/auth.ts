import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import jsonwebtoken, { type JwtPayload, type VerifyErrors } from "jsonwebtoken";
import passport, { type Profile } from "passport";
import { type VerifiedCallback } from "passport-jwt";
import { type IVerifyOptions } from "passport-local";
import qs from "qs";
import Email from "../models/Email";
import Token from "../models/Token";
import User, { type IUserDocument } from "../models/User";
import emailService from "../services/email";
import { compoundResponse, isAPIHeaders } from "../utils/helpers";
import vars from "../utils/vars";

const AuthController = {
	validator: (method: string) => {
		switch (method) {
			case "register":
				return [
					body("email")
						.notEmpty()
						.withMessage("Email must supply an E-mail.")
						.isEmail()
						.withMessage("Email must be in an E-mail format.")
						.trim()
						.normalizeEmail({
							gmail_remove_dots: false,
							gmail_remove_subaddress: false,
							outlookdotcom_remove_subaddress: false,
							yahoo_remove_subaddress: false,
							icloud_remove_subaddress: false,
						}),
					body("name").notEmpty().withMessage("You must supply a name!").trim().escape(),
					body("password")
						.notEmpty()
						.withMessage("Password can't be blank!")
						.isLength({ min: 8 })
						.withMessage("Password must be at least 8 chars long")
						.isStrongPassword()
						.withMessage(
							"Password must include one lowercase character, one uppercase character, a number, and a special character."
						),
					body("password_confirmation")
						.notEmpty()
						.withMessage("Password confirmation can't be blank!")
						.custom((value, { req }) => value === req.body.password)
						.withMessage("Your passwords don't match!"),
				];
			case "login":
				return [
					body("email")
						.notEmpty()
						.withMessage("You must be supply an Email!")
						.isEmail()
						.withMessage("Email must be in an E-mail format.")
						.trim()
						.normalizeEmail({
							gmail_remove_dots: false,
							gmail_remove_subaddress: false,
							outlookdotcom_remove_subaddress: false,
							yahoo_remove_subaddress: false,
							icloud_remove_subaddress: false,
						}),
					body("password")
						.notEmpty()
						.withMessage("Password can't be blank!")
						.isLength({ min: 8 })
						.withMessage("Password must be at least 8 chars long")
						.isStrongPassword()
						.withMessage(
							"Password must include one lowercase character, one uppercase character, a number, and a special character."
						),
					body("remember").optional().toBoolean(),
				];
			case "social-user":
				return [
					body("email")
						.notEmpty()
						.withMessage("Email must supply an E-mail.")
						.isEmail()
						.withMessage("Email must be in an E-mail format.")
						.trim()
						.normalizeEmail({
							gmail_remove_dots: false,
							gmail_remove_subaddress: false,
							outlookdotcom_remove_subaddress: false,
							yahoo_remove_subaddress: false,
							icloud_remove_subaddress: false,
						}),
					body("name").notEmpty().withMessage("You must supply a name!").trim().escape(),
					body("provider_id").notEmpty().withMessage("Provider id can't be blank!").trim(),
					body("provider_token").notEmpty().withMessage("Provider access token can't be blank!").trim(),
					body("picture").optional(),
				];
			case "refresh-token":
				return [body("refresh_token").notEmpty().withMessage("You must be supply a refresh token!")];
			case "forgot-password":
				return [
					body("email")
						.notEmpty()
						.withMessage("Email must supply an E-mail.")
						.isEmail()
						.withMessage("Email must be in an E-mail format.")
						.trim()
						.normalizeEmail({
							gmail_remove_dots: false,
							gmail_remove_subaddress: false,
							outlookdotcom_remove_subaddress: false,
							yahoo_remove_subaddress: false,
							icloud_remove_subaddress: false,
						}),
				];
			case "reset-password":
				return [
					body("password")
						.notEmpty()
						.withMessage("Password can't be blank!")
						.isLength({ min: 8 })
						.withMessage("Password must be at least 8 chars long")
						.isStrongPassword()
						.withMessage(
							"Password must include one lowercase character, one uppercase character, a number, and a special character."
						),
					body("password_confirmation")
						.notEmpty()
						.withMessage("Confirm password cannot be blank!")
						.custom(
							(
								value,
								{
									req: {
										body: { password },
									},
								}
							) => value === password
						)
						.withMessage("Your passwords don't match!"),
				];
			default:
				return [];
		}
	},
	passportSerializeUser: (user: IUserDocument, done: (err: any, id?: any) => void) => done(null, user),
	passportDeserializeUser: async (
		_id: IUserDocument["_id"],
		done: (err: any, user?: IUserDocument | false | null) => void
	) => done({ ...(await to(User.findOne({ _id }))) }),
	passportLocalStrategy: async (
		req: Request,
		email: IUserDocument["email"],
		password: IUserDocument["password"],
		done: (error: any, user?: Express.User | false, options?: IVerifyOptions) => void
	) => {
		const [error, user] = await to(
			User.findOne({ email: email.toLowerCase(), role: { $in: [vars.roles.admin, vars.roles.moderator] } })
		);
		if (error) done(error);
		if (!user) {
			req.flash("danger", "Your credentials doesn't match our records");
			return done(null, false, { message: "Your credentials doesn't match our records" });
		}

		user.comparePassword(password, (comparePasswordError, isMatch) => {
			if (comparePasswordError) return done(comparePasswordError);
			if (!isMatch) {
				req.flash("danger", "Your credentials doesn't match our records.");
				return done(null, false, { message: "Your credentials doesn't match our records" });
			}
			return done(null, user);
		});
	},
	passportJWTStrategy: async ({ sub: _id }: { sub: string }, done: VerifiedCallback) => {
		const [error, user] = await to(User.findOne({ _id }));
		if (error) return done(error);
		if (!user) return done(null, false);
		return done(null, user, { scope: "all" });
	},
	passportGoogleStrategy: async (
		req: Request,
		accessToken: string,
		_refreshToken: string,
		profile: Profile,
		done: (error: any, user?: any, info?: any) => void
	) => {
		if (req.isAuthenticated()) {
			const [existsUserError, existsUser] = await to(User.findOne({ google: profile?.id }));
			if (existsUserError) return done(existsUserError);
			if (existsUser) {
				req.flash(
					"danger",
					"There is already an account using this email address. Sign in to that account and link it with Google manually from Account Settings."
				);
				return done(null);
			}

			// eslint-disable-next-line prefer-const
			let [userError, user] = await to(User.findOne({ _id: req.user._id }));
			if (userError) return done(userError);
			if (!user) return done(new Error("No User Found"));

			user = Object.assign(user, {
				...(profile?.id ? { google: profile.id } : {}),
				...(!user?.name && profile?.displayName ? { name: profile.displayName } : {}),
				is_verified: true,
				is_active: true,
				...(!user?.role ? { role: vars.roles.moderator } : {}),
			});

			const [tokenError, token] = await to(Token.findOne({ user: user._id, kind: vars.tokenTypes.google }));
			if (tokenError) return done(tokenError);

			let newRefreshTokenError;

			if (!token) {
				[newRefreshTokenError] = await to(
					Token.create({ user: user._id, token: accessToken, kind: vars.tokenTypes.google })
				);
			} else {
				[newRefreshTokenError] = await to(
					Token.updateOne({ user: user._id, kind: vars.tokenTypes.google }, { $set: { token: accessToken } })
				);
			}

			if (newRefreshTokenError) return done(newRefreshTokenError);

			const [saveError] = await to(user.save());
			if (saveError) return done(saveError);

			req.flash("success", "Google Account has been linked!");
			return done(null, user);
		}

		const [existsUserError, existsUser] = await to(
			User.findOne({ google: profile?.id, role: vars.roles.moderator })
		);
		if (existsUserError) return done(existsUserError);
		if (existsUser) {
			const [updatedUserError] = await to(
				User.updateOne({ _id: existsUser?._id }, { $set: { is_active: 1, is_verified: 1 } })
			);
			if (updatedUserError) return done(updatedUserError);

			const [userError, user] = await to(User.findOne({ _id: existsUser?._id }));
			if (userError) return done(userError);

			req.flash("success", "Welcome Back!");
			return done(null, user);
		}

		const [existsEmailError, existsEmail] = await to(User.findOne({ email: profile?.emails?.[0]?.value || "" }));
		if (existsEmailError) return done(existsEmailError);
		if (existsEmail) {
			req.flash(
				"danger",
				`There is already an account using this email address with ${existsEmail.role.toLowerCase()} role. Sign in to that account and link it with Google manually from Account Settings.`
			);
			if (existsEmail.role === vars.roles.moderator)
				req.flash(
					"info",
					`Redirect to <strong><a href="http://${req.headers.host}/dashboard/pages/auth/password/forgot">Forgot Password?</a></strong> to reset your password.`
				);
			return done(null);
		}

		const user = {
			name: profile.displayName,
			email: profile?.emails?.[0]?.value || "",
			google: profile.id,
			is_active: true,
			is_verified: true,
			role: vars.roles.moderator,
		};

		const [newUserError, newUser] = await to(User.create(user));
		if (newUserError) return done(newUserError);

		const [newRefreshTokenError] = await to(
			Token.create({ user: newUser._id, token: accessToken, kind: vars.tokenTypes.google })
		);
		if (newRefreshTokenError) return done(newRefreshTokenError);

		req.flash("success", "Welcome Back!");
		return done(null, newUser);
	},
	passportFacebookStrategy: async (
		req: Request,
		accessToken: string,
		_refreshToken: string,
		profile: Profile,
		done: (error: any, user?: any, info?: any) => void
	) => {
		if (req.isAuthenticated()) {
			const [existsUserError, existsUser] = await to(User.findOne({ facebook: profile?.id }));
			if (existsUserError) return done(existsUserError);
			if (existsUser) {
				req.flash(
					"danger",
					"There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings."
				);
				return done(
					new Error(
						"There is already an account using this email address. Sign in to that account and link it with Facebook manually from Account Settings."
					)
				);
			}

			// eslint-disable-next-line prefer-const
			let [userError, user] = await to(User.findOne({ _id: req.user._id }));
			if (userError) return done(userError);
			if (!user) return done(new Error("No User Found"));

			user = Object.assign(user, {
				...(profile?.id ? { facebook: profile.id } : {}),
				...(!user?.name && (profile?.name?.givenName || profile?.name?.middleName || profile?.name?.familyName)
					? { name: `${profile.name.givenName} ${profile.name.middleName} ${profile.name.familyName}` }
					: {}),
				...(!user?.picture ? { picture: `https://graph.facebook.com/${profile.id}/picture?type=large` } : {}),
				is_verified: true,
				is_active: true,
				...(!user?.role ? { role: vars.roles.moderator } : {}),
			});

			const [tokenError, token] = await to(Token.findOne({ user: user._id, kind: vars.tokenTypes.facebook }));
			if (tokenError) return done(tokenError);

			let newRefreshTokenError;

			if (!token) {
				[newRefreshTokenError] = await to(
					Token.create({ user: user._id, token: accessToken, kind: vars.tokenTypes.facebook })
				);
			} else {
				[newRefreshTokenError] = await to(
					Token.updateOne(
						{ user: user._id, kind: vars.tokenTypes.facebook },
						{ $set: { token: accessToken } }
					)
				);
			}
			if (newRefreshTokenError) return done(newRefreshTokenError);

			const [saveError] = await to(user.save());
			if (saveError) return done(saveError);

			req.flash("success", "Facebook Account has been linked!");
			return done(null, user);
		}

		const [existsUserError, existsUser] = await to(User.findOne({ facebook: profile?.id }));
		if (existsUserError) return done(existsUserError);
		if (existsUser) {
			const [updatedUserError] = await to(
				User.updateOne({ _id: existsUser?._id }, { $set: { is_active: 1, is_verified: 1 } })
			);
			if (updatedUserError) return done(updatedUserError);

			const [userError, user] = await to(User.findOne({ _id: existsUser?._id }));
			if (userError) return done(userError);

			req.flash("success", "Welcome Back!");
			return done(null, user);
		}

		const [existsEmailError, existsEmail] = await to(User.findOne({ email: profile?.emails?.[0]?.value || "" }));
		if (existsEmailError) return done(existsEmailError);
		if (existsEmail) {
			req.flash(
				"danger",
				`There is already an account using this email address with ${existsEmail.role.toLowerCase()} role. Sign in to that account and link it with Google manually from Account Settings.`
			);
			if (existsEmail.role === vars.roles.moderator)
				req.flash(
					"info",
					`Redirect to <strong><a href="http://${req.headers.host}/dashboard/pages/auth/password/forgot">Forgot Password?</a></strong> to reset your password.`
				);
			return done(null);
		}

		const user = {
			name:
				profile.displayName ||
				`${profile?.name?.givenName || ""} ${profile?.name?.middleName || ""} ${
					profile?.name?.familyName || ""
				}`,
			picture: `https://graph.facebook.com/${profile.id}/picture?type=large`,
			email: profile?.emails?.[0]?.value || "",
			facebook: profile.id,
			is_active: true,
			is_verified: true,
			role: vars.roles.moderator,
		};

		const [newUserError, newUser] = await to(User.create(user));
		if (newUserError) return done(newUserError);

		const [newRefreshTokenError] = await to(
			Token.create({ user: newUser._id, token: accessToken, kind: vars.tokenTypes.facebook })
		);
		if (newRefreshTokenError) return done(newRefreshTokenError);

		req.flash("success", "Welcome Back!");
		return done(null, newUser);
	},
	postSocialUser: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY }));
		}

		if (req.isAuthenticated()) {
			const [existsUserError, existsUser] = await to(
				User.findOne({ [req.params.provider]: req.body.provider_id, role: vars.roles.user })
			);
			if (existsUserError) return next(existsUserError);
			if (existsUser) {
				req.flash(
					"danger",
					`There is already an account using this email address with ${existsUser.role.toLowerCase()} role. Sign in to that account and link it with Google manually from Account Settings.`
				);
				return next();
			}

			// eslint-disable-next-line prefer-const
			let [userError, user] = await to(User.findOne({ _id: req.user._id }));
			if (userError) return next(userError);
			if (!user) return next();

			user = Object.assign(user, {
				[req.params.provider]: req.body.provider_id,
				...(req?.body?.name ? { name: req.body.name } : {}),
				...(req?.body?.picture ? { picture: req.body.picture } : {}),
				is_verified: true,
				is_active: true,
				...(!user?.role ? { role: vars.roles.user } : {}),
			});

			const [tokenError, token] = await to(
				Token.findOne({
					user: user._id,
					kind: vars.tokenTypes?.[req.params.provider as keyof typeof vars.tokenTypes] || "",
				})
			);
			if (tokenError) return next(tokenError);

			let newSocialProviderTokenError;

			if (!token) {
				[newSocialProviderTokenError] = await to(
					Token.create({
						user: user._id,
						token: req.body.provider_token,
						kind: vars.tokenTypes[req.params.provider as keyof typeof vars.tokenTypes],
					})
				);
			} else {
				[newSocialProviderTokenError] = await to(
					Token.updateOne(
						{
							user: user._id,
							kind: vars.tokenTypes[req.params.provider as keyof typeof vars.tokenTypes],
						},
						{ $set: { token: req.body.provider_token } }
					)
				);
			}
			if (newSocialProviderTokenError) return next(newSocialProviderTokenError);

			const [saveError] = await to(user.save());
			if (saveError) return next(saveError);

			const access_token = jsonwebtoken.sign(
				{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
				vars.auth.strategies.jwt.accessTokenSecret,
				{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
			);
			const refresh_token = jsonwebtoken.sign(
				{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
				vars.auth.strategies.jwt.refreshTokenSecret,
				{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
			);

			const [newRefreshTokenError] = await to(
				Token.create({
					user: user._id,
					token: refresh_token,
					kind: vars.tokenTypes.jwt,
					expire_at: Date.now() + 1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
				})
			);
			if (newRefreshTokenError) return next(newRefreshTokenError);

			req.flash("success", `Account ${req.params.provider} has been linked`);
			res.status(httpStatus.CREATED).json(
				compoundResponse({
					status: httpStatus.CREATED,
					entities: {
						data: {
							user: { ...user.toObject(), password: undefined },
							access_token,
							refresh_token,
							token_type: vars.auth.strategies.jwt.tokenType,
						},
					},
					flashes: req.flash(),
				})
			);
		}

		const [existsUserError, existsUser] = await to(
			User.findOne({ [req.params.provider]: req.body.provider_id, role: vars.roles.user })
		);
		if (existsUserError) return next(existsUserError);
		if (existsUser) {
			const [updatedUserError] = await to(
				User.updateOne({ _id: existsUser?._id }, { $set: { is_active: 1, is_verified: 1 } })
			);
			if (updatedUserError) return next(updatedUserError);

			const [userError, user] = await to(User.findOne({ _id: existsUser?._id }));
			if (userError) return next(userError);
			if (!user) return next();

			const access_token = jsonwebtoken.sign(
				{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
				vars.auth.strategies.jwt.accessTokenSecret,
				{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
			);
			const refresh_token = jsonwebtoken.sign(
				{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
				vars.auth.strategies.jwt.refreshTokenSecret,
				{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
			);

			const [userRefreshTokenError, userRefreshToken] = await to(
				Token.findOne({ user: user._id, kind: vars.tokenTypes.jwt, expire_at: { $gt: Date.now() } })
			);
			if (userRefreshTokenError) return next(userRefreshTokenError);

			let newRefreshTokenError;

			if (!userRefreshToken) {
				[newRefreshTokenError] = await to(
					Token.create({
						user: user._id,
						token: refresh_token,
						kind: vars.tokenTypes.jwt,
						expire_at:
							Date.now() + 1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
					})
				);
			} else {
				[newRefreshTokenError] = await to(
					Token.updateOne(
						{ user: user._id, kind: vars.tokenTypes.jwt },
						{
							$set: {
								token: refresh_token,
								expire_at:
									Date.now() +
									1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
							},
						}
					)
				);
			}
			if (newRefreshTokenError) return next(newRefreshTokenError);

			req.flash("success", "Welcome Back!");
			return res.status(httpStatus.OK).json(
				compoundResponse({
					status: httpStatus.OK,
					entities: {
						data: {
							user: { ...user.toObject(), is_active: true, password: undefined },
							access_token,
							refresh_token,
							token_type: vars.auth.strategies.jwt.tokenType,
						},
					},
					flashes: req.flash(),
				})
			);
		}

		const [existsEmailError, existsEmail] = await to(User.findOne({ email: req.body.email }));
		if (existsEmailError) return next(existsEmailError);
		if (existsEmail) {
			req.flash(
				"danger",
				`There is already an account using this email address with ${existsEmail.role.toLowerCase()} role. Sign in to that account and link it with Google manually from Account Settings.`
			);
			if (existsEmail.role === vars.roles.user)
				req.flash(
					"info",
					`Redirect to <strong><a href="http://${req.headers.host}/auth/password/forgot">Forgot Password?</a></strong> to reset your password.`
				);
			return next();
		}

		const [newUserError, newUser] = await to(
			User.create({
				email: req.body.email,
				name: req.body.name,
				...(req.body.picture && { picture: req.body.picture }),
				[req.params.provider]: req.body.provider_id,
				is_active: true,
				is_verified: true,
				role: vars.roles.user,
			})
		);
		if (newUserError) return next(newUserError);

		const [newSocialProviderTokenError] = await to(
			Token.create({
				user: newUser._id,
				token: req.body.provider_token,
				kind: vars.tokenTypes[req.params.provider as keyof typeof vars.tokenTypes],
			})
		);
		if (newSocialProviderTokenError) return next(newSocialProviderTokenError);

		const access_token = jsonwebtoken.sign(
			{ sub: newUser._id.toString(), iat: Math.floor(Date.now() / 1000) },
			vars.auth.strategies.jwt.accessTokenSecret,
			{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
		);
		const refresh_token = jsonwebtoken.sign(
			{ sub: newUser._id.toString(), iat: Math.floor(Date.now() / 1000) },
			vars.auth.strategies.jwt.refreshTokenSecret,
			{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
		);

		const [newRefreshTokenError] = await to(
			Token.create({
				user: newUser._id,
				token: refresh_token,
				kind: vars.tokenTypes.jwt,
				expire_at: Date.now() + 1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
			})
		);
		if (newRefreshTokenError) return next(newRefreshTokenError);

		req.flash("success", "Account Registered Successfully");
		res.status(httpStatus.CREATED).json(
			compoundResponse({
				status: httpStatus.CREATED,
				entities: {
					data: {
						user: { ...newUser.toObject(), password: undefined },
						access_token,
						refresh_token,
						token_type: vars.auth.strategies.jwt.tokenType,
					},
				},
				flashes: req.flash(),
			})
		);
	},
	getSocialUser: (req: Request, res: Response, next: NextFunction) =>
		passport.authenticate(req.params.provider, {
			scope: vars.auth.strategies[req.params.provider as "google" | "facebook"].scope || "",
		})(req, res, next),
	getSocialRedirect: (req: Request, res: Response, next: NextFunction) =>
		passport.authenticate(req.params.provider, {
			...(vars?.auth?.strategies?.[req?.params?.provider as "google" | "facebook"]?.redirect || {}),
		})(req, res, next),
	getSocialUnlink: async (req: Request, res: Response, next: NextFunction) => {
		const { provider } = req.params;
		const _id = req.user?.id || "";

		const [deleteTokenError] = await to(
			Token.deleteOne({ user: _id, kind: vars.tokenTypes[provider as keyof typeof vars.tokenTypes] })
		);
		if (deleteTokenError) return next(deleteTokenError);

		const [updateUserError] = await to(User.updateOne({ _id }, { $unset: { [provider]: 1 } }));
		if (updateUserError) return next(updateUserError);

		req.flash("success", `${provider} account has been unlinked.`);
		res.format({
			html: () => res.status(httpStatus.OK).redirect(req.session.returnTo || "/dashboard"),
			json: () =>
				res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() })),
		});
	},
	getRegister: (_req: Request, res: Response) =>
		res.render("dashboard/pages/auth/register", compoundResponse({ pageTitle: "Register", title: "Register" })),
	getLogin: (_req: Request, res: Response) =>
		res.render("dashboard/pages/auth/login", compoundResponse({ pageTitle: "login", title: "Login" })),
	getForgotPassword: (_req: Request, res: Response) =>
		res.render(
			"dashboard/pages/auth/password/forgot",
			compoundResponse({ pageTitle: "Forgot Password", title: "Forgot Password" })
		),
	getForgotPasswordConfirm: (_req: Request, res: Response) =>
		res.render(
			"dashboard/pages/auth/password/confirm",
			compoundResponse({
				pageTitle: "Forgot Password Confirmation",
				title: "Forgot Password Confirmation",
			})
		),
	getResetPassword: (_req: Request, res: Response) =>
		res.render(
			"dashboard/pages/auth/password/reset",
			compoundResponse({ pageTitle: "Reset Password", title: "Reset Password" })
		),
	postRegister: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return res.format({
				html: () =>
					res.status(httpStatus.UNPROCESSABLE_ENTITY).render(
						"dashboard/pages/auth/register",
						compoundResponse({
							pageTitle: "Register",
							title: "Register",
							entities: {
								data: {
									body: { ...req.body, password: undefined, password_confirmation: undefined },
								},
							},
						})
					),
				json: () => next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() })),
			});
		}

		const { email } = req.body;
		const [userError, user] = await to(User.findOne({ email }));
		if (userError) return next(userError);
		if (user && Object.keys(user)?.length) {
			req.flash(
				"danger",
				`Account already exists, try to <strong><a href="http://${req.headers.host}/dashboard/pages/auth/login">login</a></strong> instead.`
			);
			return res.format({
				html: () =>
					res.status(httpStatus.CONFLICT).render(
						"dashboard/pages/auth/register",
						compoundResponse({
							pageTitle: "Register",
							title: "Register",
							entities: {
								data: {
									body: { ...req.body, password: undefined, password_confirmation: undefined },
								},
							},
						})
					),
				json: () =>
					res
						.status(httpStatus.CONFLICT)
						.json(compoundResponse({ status: httpStatus.CONFLICT, flashes: req.flash() })),
			});
		}

		const [createdUserError, createdUser] = await to(
			User.create({
				...req.body,
				is_active: true,
				...(!isAPIHeaders(req) && { role: vars.roles.moderator }),
			})
		);
		if (createdUserError) return next(createdUserError);

		const token = await createdUser.createHashToken();
		const [newVerifyEmailTokenError] = await to(
			Token.create({
				user: createdUser._id,
				token,
				kind: vars.tokenTypes.verifyEmail,
				expire_at: Date.now() + 1000 * 60 * vars.email.emailVerifyTokenExpiresInMinutes,
			})
		);
		if (newVerifyEmailTokenError) return next(newVerifyEmailTokenError);

		const [sendEmailError, sendEmail] = await emailService.send({
			to: createdUser,
			from: vars.email.sender,
			filename: "verify-user",
			subject: `[${vars.app.name}] Verify User Account.`,
			actionUrl: `http://${req.headers.host}${!isAPIHeaders(req) ? "/dashboard" : ""}/auth/email/verify/${token}`,
		});
		if (sendEmailError) return next(sendEmailError);

		const [newEmailError] = await to(Email.create(sendEmail));
		if (newEmailError) return next(newEmailError);

		req.flash("success", "Account Registered Successfully, Check your E-mail address to verify your account.");
		res.format({
			html: () => {
				req.login(createdUser, async (loginError) => {
					if (loginError) return next(loginError);

					if (req.body.remember) {
						const expire = 1000 * 60 * 60 * vars.cookies.maxAgeInHours;
						req.session.cookie.expires = new Date(Date.now() + expire);
						req.session.cookie.maxAge = expire;
					} else {
						req.session.cookie.expires = null;
					}

					res.status(httpStatus.OK).redirect(req.session.returnTo || "/dashboard");
				});
			},
			json: async () => {
				const access_token = jsonwebtoken.sign(
					{ sub: createdUser._id.toString(), iat: Math.floor(Date.now() / 1000) },
					vars.auth.strategies.jwt.accessTokenSecret,
					{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
				);
				const refresh_token = jsonwebtoken.sign(
					{ sub: createdUser._id.toString(), iat: Math.floor(Date.now() / 1000) },
					vars.auth.strategies.jwt.refreshTokenSecret,
					{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
				);

				const [newRefreshTokenError] = await to(
					Token.create({
						user: createdUser._id,
						token: refresh_token,
						kind: vars.tokenTypes.jwt,
						expire_at:
							Date.now() + 1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
					})
				);
				if (newRefreshTokenError) return next(newRefreshTokenError);

				res.status(httpStatus.CREATED).json(
					compoundResponse({
						status: httpStatus.CREATED,
						entities: {
							data: {
								user: { ...createdUser.toObject(), password: undefined },
								access_token,
								refresh_token,
								token_type: vars.auth.strategies.jwt.tokenType,
							},
						},
						flashes: req.flash(),
					})
				);
			},
		});
	},
	postLogin: (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return res.format({
				html: () =>
					res.status(httpStatus.UNPROCESSABLE_ENTITY).render(
						"dashboard/pages/auth/login",
						compoundResponse({
							pageTitle: "login",
							title: "Login",
							entities: {
								data: {
									body: { ...req.body, password: undefined },
								},
							},
						})
					),
				json: () => next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() })),
			});
		}

		res.format({
			html: () => {
				passport.authenticate("local", async (err: Error, user: IUserDocument) => {
					if (err) next(err);
					if (!user)
						return res.status(httpStatus.NOT_FOUND).render(
							"dashboard/pages/auth/login",
							compoundResponse({
								pageTitle: "Login",
								title: "Login",
								entities: {
									data: {
										body: { ...req.body, password: undefined },
									},
								},
							})
						);

					req.login(user, async (loginError) => {
						if (loginError) return next(loginError);

						if (req.body.remember) {
							const expire = 1000 * 60 * 60 * vars.cookies.maxAgeInHours;
							req.session.cookie.expires = new Date(Date.now() + expire);
							req.session.cookie.maxAge = expire;
						} else {
							req.session.cookie.expires = null;
						}

						const [updateUserError] = await to(
							User.updateOne({ email: user.email, is_active: false }, { $set: { is_active: true } })
						);
						if (updateUserError) return next();

						req.flash("success", "Welcome Back!");
						res.status(httpStatus.OK).redirect(req.session.returnTo || "/dashboard");
					});
				})(req, res, next);
			},
			json: async () => {
				const { email } = req.body;
				const [userError, user] = await to(User.findOne({ email }));
				if (userError) return next(userError);
				if (!user) return next();

				user.comparePassword(req.body.password, async (compareError, isMatch) => {
					if (compareError) return next(compareError);
					if (!isMatch) {
						req.flash("danger", "Your credentials doesn't match our records.");
						return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY }));
					}

					const [updateUserError] = await to(
						User.updateOne({ email: user.email, is_active: false }, { $set: { is_active: true } })
					);
					if (updateUserError) return next(updateUserError);

					const access_token = jsonwebtoken.sign(
						{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
						vars.auth.strategies.jwt.accessTokenSecret,
						{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
					);
					const refresh_token = jsonwebtoken.sign(
						{ sub: user._id.toString(), iat: Math.floor(Date.now() / 1000) },
						vars.auth.strategies.jwt.refreshTokenSecret,
						{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
					);

					const [userRefreshTokenError, userRefreshToken] = await to(
						Token.findOne({ user: user._id, kind: vars.tokenTypes.jwt, expire_at: { $gt: Date.now() } })
					);
					if (userRefreshTokenError) return next(userRefreshTokenError);
					let newRefreshTokenError;

					if (!userRefreshToken) {
						[newRefreshTokenError] = await to(
							Token.create({
								user: user._id,
								token: refresh_token,
								kind: vars.tokenTypes.jwt,
								expire_at:
									Date.now() +
									1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
							})
						);
					} else {
						[newRefreshTokenError] = await to(
							Token.updateOne(
								{ user: user._id, kind: vars.tokenTypes.jwt },
								{
									$set: {
										token: refresh_token,
										expire_at:
											Date.now() +
											1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
									},
								}
							)
						);
					}
					if (newRefreshTokenError) return next(newRefreshTokenError);

					req.flash("success", "Welcome Back!");
					return res.status(httpStatus.OK).json(
						compoundResponse({
							status: httpStatus.OK,
							entities: {
								data: {
									user: { ...user.toObject(), is_active: true, password: undefined },
									access_token,
									refresh_token,
									token_type: vars.auth.strategies.jwt.tokenType,
								},
							},
							flashes: req.flash(),
						})
					);
				});
			},
		});
	},
	logout: async (req: Request, res: Response, next: NextFunction) => {
		const _id = req?.user?._id || "";

		const [deleteTokenError] = await to(
			Token.deleteMany({
				user: _id,
				kind: {
					$in: [vars.tokenTypes.jwt, vars.tokenTypes.resetPassword, vars.tokenTypes.verifyEmail],
				},
			})
		);
		if (deleteTokenError) return next(deleteTokenError);

		const [updateUserError] = await to(User.updateOne({ _id }, { $set: { is_active: false } }));
		if (updateUserError) return next(updateUserError);

		req.flash("success", "Successfully logged out!");
		res.format({
			html: () =>
				req.logout(() => {
					req.user = undefined;
					return res.redirect("/dashboard/auth/login");
				}),
			json: async () =>
				res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() })),
		});
	},
	postRefreshToken: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { refresh_token: refreshToken } = req.body as { refresh_token: string };
		const [userRefreshTokenError, userRefreshToken] = await to(
			Token.findOne({ token: refreshToken, kind: vars.tokenTypes.jwt, expire_at: { $gt: Date.now() } })
		);
		if (userRefreshTokenError) return next(userRefreshTokenError);
		if (!userRefreshToken) {
			req.flash("danger", "Token has been expired, please login again!");
			return res
				.status(httpStatus.FORBIDDEN)
				.json(compoundResponse({ status: httpStatus.FORBIDDEN, flashes: req.flash() }));
		}

		jsonwebtoken.verify(
			refreshToken,
			vars.auth.strategies.jwt.refreshTokenSecret,
			async (error: VerifyErrors | null, payload: JwtPayload | string | undefined) => {
				if (error) return next(compoundResponse({ status: httpStatus.FORBIDDEN, error }));
				const _id = payload?.sub || "";
				const access_token = jsonwebtoken.sign(
					{ sub: _id.toString(), iat: Math.floor(Date.now() / 1000) },
					vars.auth.strategies.jwt.accessTokenSecret,
					{ expiresIn: `${vars.auth.strategies.jwt.accessTokenExpiresInMinutes}m` }
				);
				const refresh_token = jsonwebtoken.sign(
					{ sub: _id.toString(), iat: Math.floor(Date.now() / 1000) },
					vars.auth.strategies.jwt.refreshTokenSecret,
					{ expiresIn: `${vars.auth.strategies.jwt.refreshTokenExpiresInDays}d` }
				);

				const [newRefreshTokenError] = await to(
					Token.updateOne(
						{ token: refreshToken, kind: vars.tokenTypes.jwt, expire_at: { $gt: Date.now() } },
						{
							$set: {
								token: refresh_token,
								expire_at:
									Date.now() +
									1000 * 60 * 60 * 24 * vars.auth.strategies.jwt.refreshTokenExpiresInDays,
							},
						}
					)
				);
				if (newRefreshTokenError) return next(newRefreshTokenError);

				return res.status(httpStatus.OK).json(
					compoundResponse({
						status: httpStatus.OK,
						entities: {
							data: { access_token, refresh_token, token_type: vars.auth.strategies.jwt.tokenType },
						},
					})
				);
			}
		);
	},
	postForgotPassword: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return res.format({
				html: () =>
					res.status(httpStatus.UNPROCESSABLE_ENTITY).render(
						"dashboard/pages/auth/password/forgot",
						compoundResponse({
							pageTitle: "Forgot Password",
							title: "Forgot Password",
							entities: {
								data: {
									body: req.body,
								},
							},
						})
					),
				json: () => next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() })),
			});
		}

		const { email } = req.body;
		const [userError, user] = await to(User.findOne({ email }));
		if (userError) return next(userError);
		if (!user) {
			req.flash("danger", "No account found with this email.");
			return res.format({
				html: () =>
					res.status(httpStatus.NOT_FOUND).render(
						"dashboard/pages/auth/password/forgot",
						compoundResponse({
							pageTitle: "Forgot Password",
							title: "Forgot Password",
							entities: {
								data: {
									body: req.body,
								},
							},
						})
					),
				json: () =>
					res.status(httpStatus.NOT_FOUND).json(
						compoundResponse({
							status: httpStatus.NOT_FOUND,
							flashes: req.flash(),
						})
					),
			});
		}

		const token = await user.createHashToken();
		const [resetPasswordTokenError, resetPasswordToken] = await to(
			Token.findOne({ user: user._id, kind: vars.tokenTypes.resetPassword, expire_at: { $gt: Date.now() } })
		);
		if (resetPasswordTokenError) return next(resetPasswordTokenError);

		let newRefreshTokenError;

		if (!resetPasswordToken) {
			[newRefreshTokenError] = await to(
				Token.create({
					user: user._id,
					token,
					kind: vars.tokenTypes.resetPassword,
					expire_at: Date.now() + 1000 * 60 * 60 * vars.password.resetTimeLimitInHours,
				})
			);
		} else {
			[newRefreshTokenError] = await to(
				Token.updateOne(
					{ user: user._id, kind: vars.tokenTypes.resetPassword, expire_at: { $gt: Date.now() } },
					{
						$set: {
							token,
							expire_at: Date.now() + 1000 * 60 * 60 * vars.password.resetTimeLimitInHours,
						},
					}
				)
			);
		}

		if (newRefreshTokenError) return next(newRefreshTokenError);

		const [sendEmailError, sendEmail] = await emailService.send({
			to: user,
			from: vars.email.sender,
			filename: "password-reset",
			subject: `[${vars.app.name}] Resetting Password.`,
			actionUrl: `http://${req.headers.host}${
				!isAPIHeaders(req) ? "/dashboard" : ""
			}/auth/password/reset/${token}`,
		});
		if (sendEmailError) return next(sendEmailError);

		const [newEmailError] = await to(Email.create(sendEmail));
		if (newEmailError) return next(newEmailError);

		req.flash("success", "You have been emailed a reset password link.");
		res.format({
			html: () =>
				res
					.status(httpStatus.OK)
					.redirect(`/dashboard/auth/password/forgot/confirm?${qs.stringify({ email })}`),
			json: () =>
				res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() })),
		});
	},
	postResetPassword: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return res.format({
				html: () =>
					res.status(httpStatus.UNPROCESSABLE_ENTITY).render(
						"dashboard/pages/auth/password/reset",
						compoundResponse({
							pageTitle: "Reset Password",
							title: "Reset Password",
							entities: {
								data: {
									body: { ...req.body, password: undefined, password_confirmation: undefined },
								},
							},
						})
					),
				json: () => next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() })),
			});
		}

		const [resetPasswordTokenError, resetPasswordToken] = await to(
			Token.findOne({
				token: req.params.token,
				kind: vars.tokenTypes.resetPassword,
				expire_at: { $gt: Date.now() },
			})
		);
		if (resetPasswordTokenError) return next(resetPasswordTokenError);
		if (!resetPasswordToken) {
			req.flash("danger", "token is invalid or has expired.");
			return res.format({
				html: () =>
					res.status(httpStatus.NOT_FOUND).render(
						"dashboard/pages/auth/password/reset",
						compoundResponse({
							pageTitle: "Reset Password",
							title: "Reset Password",
							entities: {
								data: {
									body: {
										...(req?.body || {}),
										password: undefined,
										password_confirmation: undefined,
									},
								},
							},
						})
					),
				json: () =>
					res.status(httpStatus.NOT_FOUND).json(
						compoundResponse({
							status: httpStatus.NOT_FOUND,
							flashes: req.flash(),
						})
					),
			});
		}

		let userError = null;
		let user = null;

		[userError, user] = await to(User.findOne({ _id: resetPasswordToken.user }));
		if (userError) return next(userError);
		if (!user) return next();

		user = Object.assign(user, { ...(req?.body?.password ? { password: req.body.password } : {}) });

		const [newUserError, newUser] = await to(user.save());
		if (newUserError) return next(newUserError);

		const [deleteResetPasswordTokenError] = await to(
			Token.deleteOne({
				user: newUser._id,
				kind: vars.tokenTypes.resetPassword,
				expire_at: { $gt: Date.now() },
			})
		);
		if (deleteResetPasswordTokenError) return next(deleteResetPasswordTokenError);

		const [sendEmailError, sendEmail] = await emailService.send({
			to: newUser,
			from: vars.email.sender,
			filename: "password-updated",
			subject: `[${vars.app.name}] Resetting Password Confirmation.`,
			siteName: vars.app.name,
		});
		if (sendEmailError) return next(sendEmailError);

		const [newEmailError] = await to(Email.create(sendEmail));
		if (newEmailError) return next(newEmailError);

		req.flash("success", "successfully updated password.");
		res.format({
			html: () => res.status(httpStatus.OK).redirect("/dashboard/auth/login"),
			json: () =>
				res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() })),
		});
	},
	getEmailVerification: async (req: Request, res: Response, next: NextFunction) => {
		const [verifyEmailTokenError, verifyEmailToken] = await to(
			Token.findOne({
				token: req.params.token,
				kind: vars.tokenTypes.verifyEmail,
				expire_at: { $gt: Date.now() },
			})
		);
		if (verifyEmailTokenError) return next(verifyEmailTokenError);
		if (!verifyEmailToken) {
			req.flash("danger", "token is invalid or has expired.");
			return res.format({
				html: () => res.status(httpStatus.NOT_FOUND).redirect("/dashboard"),
				json: () =>
					res
						.status(httpStatus.NOT_FOUND)
						.json(compoundResponse({ status: httpStatus.NOT_FOUND, flashes: req.flash() })),
			});
		}

		const [userError] = await to(
			User.findOneAndUpdate({ _id: verifyEmailToken.user, is_verified: { $lt: 1 } }, { $set: { is_verified: 1 } })
		);
		if (userError) return next(userError);

		const [deleteVerifyEmailTokenError] = await to(
			Token.deleteOne({
				token: req.params.token,
				kind: vars.tokenTypes.verifyEmail,
				expire_at: { $gt: Date.now() },
			})
		);
		if (deleteVerifyEmailTokenError) return next(deleteVerifyEmailTokenError);

		req.flash("success", "Your account has been Verified");
		return res.format({
			html: () => res.status(httpStatus.OK).redirect("/dashboard"),
			json: () =>
				res.status(httpStatus.OK).json(
					compoundResponse({
						status: httpStatus.OK,
						flashes: req.flash(),
					})
				),
		});
	},
	getResendEmailVerification: async (req: Request, res: Response, next: NextFunction) => {
		const [userError, user] = await to(User.findOne({ _id: req?.user?._id || "", is_verified: { $lt: 1 } }));
		if (userError) return next(userError);
		if (!user) {
			req.flash("danger", "Email Already Verified!");
			return res.format({
				html: () => res.status(httpStatus.NOT_FOUND).redirect("/dashboard"),
				json: () =>
					res
						.status(httpStatus.NOT_FOUND)
						.json(compoundResponse({ status: httpStatus.NOT_FOUND, flashes: req.flash() })),
			});
		}

		const [userRefreshTokenError, userRefreshToken] = await to(
			Token.findOne({ user: user._id, kind: vars.tokenTypes.verifyEmail, expire_at: { $gt: Date.now() } })
		);
		if (userRefreshTokenError) return next(userRefreshTokenError);

		const token = await user.createHashToken();

		let newRefreshTokenError;
		if (!userRefreshToken) {
			[newRefreshTokenError] = await to(
				Token.create({
					user: user._id,
					token,
					kind: vars.tokenTypes.verifyEmail,
					expire_at: Date.now() + 1000 * 60 * vars.email.emailVerifyTokenExpiresInMinutes,
				})
			);
		} else {
			[newRefreshTokenError] = await to(
				Token.updateOne(
					{ user: user._id, kind: vars.tokenTypes.verifyEmail },
					{
						$set: {
							token,
							expire_at: Date.now() + 1000 * 60 * vars.email.emailVerifyTokenExpiresInMinutes,
						},
					}
				)
			);
		}

		if (newRefreshTokenError) return next(newRefreshTokenError);

		const [sendEmailError, sendEmail] = await emailService.send({
			to: user,
			from: vars.email.sender,
			filename: "verify-user",
			subject: `[${vars.app.name}] Verify User Account.`,
			actionUrl: `http://${req.headers.host}${!isAPIHeaders(req) ? "/dashboard" : ""}/auth/email/verify/${token}`,
		});
		if (sendEmailError) return next(sendEmailError);

		const [newEmailError] = await to(Email.create(sendEmail));
		if (newEmailError) return next(newEmailError);

		req.flash("success", "Email Verification sent successfully!");
		res.format({
			html: () => res.status(httpStatus.OK).redirect("/dashboard"),
			json: () =>
				res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() })),
		});
	},
};

export default AuthController;
