import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import Email from "../models/Email";
import Session from "../models/Session";
import Token from "../models/Token";
import User from "../models/User";
import emailService from "../services/email";
import { formatResponseObject, isAPIHeaders } from "../utils/helpers";
import vars from "../utils/vars";

const UsersController = {
	validator: (method: string) => {
		switch (method) {
			case "update":
				return [
					body("email")
						.optional()
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
					body("name").optional().notEmpty().withMessage("You must supply a name!").trim().escape(),
					body("old_password")
						.if(body("password").exists())
						.notEmpty()
						.withMessage("Old Password can't be blank!")
						.isLength({ min: 8 })
						.withMessage("Password must be at least 8 chars long")
						.isStrongPassword()
						.withMessage(
							"Password must include one lowercase character, one uppercase character, a number, and a special character."
						),
					body("password")
						.if(body("old_password").exists())
						.notEmpty()
						.withMessage("Password can't be blank!")
						.isLength({ min: 8 })
						.withMessage("Password must be at least 8 chars long")
						.isStrongPassword()
						.withMessage(
							"Password must include one lowercase character, one uppercase character, a number, and a special character."
						),
					body("password_confirmation")
						.if(body("password").exists())
						.notEmpty()
						.withMessage("Password confirmation can't be blank!")
						.custom((value, { req }) => value === req.body.password)
						.withMessage("Your passwords don't match!"),
					body("logout").optional().toBoolean(),
				];
			default:
				return [];
		}
	},
	getUsers: async (req: Request, res: Response, next: NextFunction) => {
		const { q, status: verified, ...query } = req.query;
		const querySearchFields = ["name", "email", "role"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { created_at: 1 } },
			{ name: "Created Date Descending", value: { created_at: -1 } },
		];

		const [paginatedUsersError, paginatedUsers] = await to(
			User.paginate(
				{
					...((q && {
						$or: querySearchFields.map((item) => ({
							[item]: { $regex: String(q).toLowerCase() || "", $options: "i" },
						})),
					}) ||
						{}),
					...((verified && verified !== "all" && { verified }) || {}),
					_id: { $ne: req?.user?._id || "" },
				},
				{ ...query }
			)
		);
		if (paginatedUsersError) return next(paginatedUsersError);

		const { docs, ...pagination } = paginatedUsers;

		return res.status(httpStatus.OK).json(
			formatResponseObject({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
	getSingleUser: async (req: Request, res: Response, next: NextFunction) => {
		const { user: userIdentifier } = req.params;
		const [userError, user] = await to(
			User.findOne({
				$or: [
					{ slug: userIdentifier },
					...(userIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: userIdentifier }] : []),
				],
			})
		);
		if (userError) return next(userError);
		if (!user) return next();

		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, entities: { data: user } }));
	},
	getCurrentAuthenticatedUser: async (req: Request, res: Response, next: NextFunction) => {
		const _id = req?.user?._id || "";
		const [userError, user] = await to(User.findOne({ _id }));
		if (userError) return next(userError);
		if (!user) return next();

		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, entities: { data: user } }));
	},
	updateSingleUser: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.parse(JSON.stringify(validationErrors.array({ onlyFirstError: true }))));
			return next(formatResponseObject({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { user: userIdentifier } = req.params;
		const {
			old_password: _old_password,
			password_confirmation: _password_confirmation,
			logout,
			...reqBody
		} = req.body;
		let isPasswordModified;
		let isEmailModified;

		// eslint-disable-next-line prefer-const
		let [userError, user] = await to(
			User.findOne({
				$or: [
					{ slug: userIdentifier },
					...(userIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: userIdentifier }] : []),
				],
			})
		);
		if (userError) return next(userError);
		if (!user) return next();

		if (reqBody?.email && user?.email) isEmailModified = reqBody.email !== user.email || false;
		if (reqBody?.password) {
			user.comparePassword(reqBody.password, (comparePasswordError, isMatch) => {
				if (comparePasswordError) return next(comparePasswordError);
				isPasswordModified = !isMatch;
			});
		}

		user = Object.assign(user, { ...reqBody, ...(isEmailModified ? { verified: false } : {}) });
		if (!user) return next();

		const [saveError, newUser] = await to(user.save());
		if (saveError) return next(saveError);

		if (isEmailModified) {
			const token = await newUser.createHashToken();
			const [newVerifyEmailToken] = await to(
				Token.create({
					user: newUser._id,
					token,
					kind: vars.tokenTypes.verifyEmail,
					expireAt: Date.now() + 1000 * 60 * vars.email.emailVerifyTokenExpiresInMinutes,
				})
			);
			if (newVerifyEmailToken) return next(newVerifyEmailToken);

			const [sendEmailError, sendEmail] = await emailService.send({
				to: newUser,
				from: vars.email.sender,
				filename: "verify-user",
				subject: `[${vars.app.name}] Verify User Account.`,
				actionUrl: `http://${req.headers.host}${
					!isAPIHeaders(req) ? "/dashboard" : ""
				}/auth/email/verify/${token}`,
			});
			if (sendEmailError) return next(sendEmailError);

			const [newEmailError] = await to(Email.create(sendEmail));
			if (newEmailError) return next(newEmailError);
		}

		if (isPasswordModified) {
			const [sendEmailError, sendEmail] = await emailService.send({
				to: newUser,
				from: vars.email.sender,
				filename: "password-updated",
				subject: `[${vars.app.name}] Password Updated Successfully.`,
				siteName: vars.app.name,
			});
			if (sendEmailError) return next(sendEmailError);

			const [newEmailError] = await to(Email.create(sendEmail));
			if (newEmailError) return next(newEmailError);
		}

		if (logout && !isAPIHeaders(req)) {
			const [deleteSessionsError] = await to(
				Session.deleteMany({
					$or: [
						{ "session.passport.user.slug": userIdentifier },
						...(userIdentifier.match(/^[0-9a-fA-F]{24}$/)
							? [{ "session.passport.user._id": userIdentifier }]
							: []),
					],
				})
			);
			if (deleteSessionsError) return next(deleteSessionsError);
		}

		req.flash("success", "successfully updated.");
		res.status(httpStatus.OK).json(
			formatResponseObject({ status: httpStatus.OK, entities: { data: newUser }, flashes: req.flash() })
		);
	},
	deleteSingleUser: async (req: Request, res: Response, next: NextFunction) => {
		const { user: userIdentifier } = req.params;

		const [userError, user] = await to(
			User.findOne({
				$or: [
					{ slug: userIdentifier },
					...(userIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: userIdentifier }] : []),
				],
			})
		);
		if (userError) return next(userError);
		if (!user) return next();

		const [deleteUserError] = await to(user.deleteOne());
		if (deleteUserError) return next(deleteUserError);

		const [deleteSessionsError] = await to(Session.deleteMany({ "session.passport.user._id": user?._id }));
		if (deleteSessionsError) return next(deleteSessionsError);

		const [deleteTokenError] = await to(Token.deleteMany({ user: user?._id }));
		if (deleteTokenError) return next(deleteTokenError);

		req.flash("success", "Successfully Deleted.");
		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, flashes: req.flash() }));
	},
};

export default UsersController;
