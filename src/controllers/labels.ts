import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import Label from "../models/Label";
import { formatResponseObject } from "../utils/helpers";

const LabelController = {
	validator: (method: string) => {
		switch (method) {
			case "store":
			case "update":
				return [
					body("name").notEmpty().withMessage("You must supply a name!").trim().escape(),
					body("emoji").notEmpty().withMessage("You must supply an Emoji!").trim(),
				];
			default:
				return [];
		}
	},
	postSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.parse(JSON.stringify(validationErrors.array({ onlyFirstError: true }))));
			return next(formatResponseObject({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const [createdLabelError, createdLabel] = await to(
			Label.create({ ...(req?.body || {}), user: req?.user?._id || "" })
		);
		if (createdLabelError) return next(createdLabelError);

		req.flash("success", "Successfully created!");
		res.status(httpStatus.CREATED).json(
			formatResponseObject({
				status: httpStatus.CREATED,
				entities: { data: { ...(createdLabel.toJSON() || {}) } },
				flashes: req.flash(),
			})
		);
	},
	getLabels: async (req: Request, res: Response, next: NextFunction) => {
		const { q, ...query } = req.query || {};
		const querySearchFields = ["name"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { createdAt: 1 } },
			{ name: "Created Date Descending", value: { createdAt: -1 } },
		];

		const [paginatedLabelsError, paginatedLabels] = await to(
			Label.paginate(
				{
					...((q && {
						$or: querySearchFields.map((item) => ({
							[item]: { $regex: String(q).toLowerCase() || "", $options: "i" },
						})),
					}) ||
						{}),
					deleted: { $ne: true },
					user: req?.user?._id || "",
				},
				{ ...query }
			)
		);
		if (paginatedLabelsError) return next(paginatedLabelsError);

		const { docs, ...pagination } = paginatedLabels;

		return res.status(httpStatus.OK).json(
			formatResponseObject({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
	getSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params || {};
		const [labelError, label] = await to(
			Label.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: labelIdentifier },
					...(labelIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: labelIdentifier }] : []),
				],
			})
		);
		if (labelError) return next(labelError);
		if (!label) return next();

		res.status(httpStatus.OK).json(
			formatResponseObject({ status: httpStatus.OK, entities: { data: { ...(label?.toJSON() || {}) } } })
		);
	},
	updateSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.parse(JSON.stringify(validationErrors.array({ onlyFirstError: true }))));
			return next(formatResponseObject({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { label: labelIdentifier } = req.params || {};

		// eslint-disable-next-line prefer-const
		let [labelError, label] = await to(
			Label.findOneAndUpdate(
				{
					user: req?.user?._id || "",
					$or: [
						{ slug: labelIdentifier },
						...(labelIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: labelIdentifier }] : []),
					],
				},
				{ ...(req?.body || {}) },
				{ new: true }
			)
		);
		if (labelError) return next(labelError);
		if (!label) return next();

		req.flash("success", "successfully updated.");
		res.status(httpStatus.OK).json(
			formatResponseObject({
				status: httpStatus.OK,
				entities: { data: { ...(label?.toJSON() || {}) } },
				flashes: req.flash(),
			})
		);
	},
	deleteSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params || {};

		const [labelError, label] = await to(
			Label.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: labelIdentifier },
					...(labelIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: labelIdentifier }] : []),
				],
			})
		);
		if (labelError) return next(labelError);
		if (!label) return next();

		const [deleteLabelError] = await to(Label.deleteById(label?._id));
		if (deleteLabelError) return next(deleteLabelError);

		req.flash("success", "Successfully Deleted.");
		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, flashes: req.flash() }));
	},
	restoreSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params || {};

		const [labelError, label] = await to(
			Label.findOneWithDeleted({
				user: req?.user?._id || "",
				$or: [
					{ slug: labelIdentifier },
					...(labelIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: labelIdentifier }] : []),
				],
			})
		);
		if (labelError) return next(labelError);
		if (!label) return next();

		const [restoreLabelError] = await to(Label.restore());
		if (restoreLabelError) return next(restoreLabelError);

		req.flash("success", "Successfully Restored.");
		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, flashes: req.flash() }));
	},
	getDeletedLabels: async (req: Request, res: Response, next: NextFunction) => {
		const { q, ...query } = req.query || {};
		const querySearchFields = ["name"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { createdAt: 1 } },
			{ name: "Created Date Descending", value: { createdAt: -1 } },
		];

		const [paginatedLabelsError, paginatedLabels] = await to(
			Label.paginate(
				{
					...((q && {
						$or: querySearchFields.map((item) => ({
							[item]: { $regex: String(q).toLowerCase() || "", $options: "i" },
						})),
					}) ||
						{}),
					deleted: true,
					user: req?.user?._id || "",
				},
				{ ...query }
			)
		);
		if (paginatedLabelsError) return next(paginatedLabelsError);

		const { docs, ...pagination } = paginatedLabels;

		return res.status(httpStatus.OK).json(
			formatResponseObject({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
};

export default LabelController;
