import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import Label from "../models/Label";
import { compoundResponse } from "../utils/helpers";

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
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const [createdLabelError, createdLabel] = await to(
			Label.create({ ...(req?.body || {}), user: req?.user?._id || "" })
		);
		if (createdLabelError) return next(createdLabelError);

		req.flash("success", "Successfully created!");
		res.status(httpStatus.CREATED).json(
			compoundResponse({
				status: httpStatus.CREATED,
				entities: { data: { label: createdLabel } },
				flashes: req.flash(),
			})
		);
	},
	getLabels: async (req: Request, res: Response, next: NextFunction) => {
		const { q, ...query } = req.query;
		const querySearchFields = ["name"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { created_at: 1 } },
			{ name: "Created Date Descending", value: { created_at: -1 } },
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
					user: req?.user?._id || "",
				},
				{ ...query }
			)
		);
		if (paginatedLabelsError) return next(paginatedLabelsError);

		const { docs, ...pagination } = paginatedLabels;

		return res.status(httpStatus.OK).json(
			compoundResponse({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
	getSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params;
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

		res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, entities: { data: label } }));
	},
	updateSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { label: labelIdentifier } = req.params;

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
			compoundResponse({ status: httpStatus.OK, entities: { data: label }, flashes: req.flash() })
		);
	},
	deleteSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params;

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
		res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() }));
	},
	restoreSingleLabel: async (req: Request, res: Response, next: NextFunction) => {
		const { label: labelIdentifier } = req.params;

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
		res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() }));
	},
};

export default LabelController;
