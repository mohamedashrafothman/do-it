import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import List from "../models/List";
import { compoundResponse } from "../utils/helpers";

const ListController = {
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
	postSingleList: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const [createdListError, createdList] = await to(
			List.create({ ...(req?.body || {}), user: req?.user?._id || "" })
		);
		if (createdListError) return next(createdListError);

		req.flash("success", "Successfully created!");
		res.status(httpStatus.CREATED).json(
			compoundResponse({
				status: httpStatus.CREATED,
				entities: { data: { list: createdList } },
				flashes: req.flash(),
			})
		);
	},
	getLists: async (req: Request, res: Response, next: NextFunction) => {
		const { q, ...query } = req.query;
		const querySearchFields = ["name"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { created_at: 1 } },
			{ name: "Created Date Descending", value: { created_at: -1 } },
		];

		const [paginatedListsError, paginatedLists] = await to(
			List.paginate(
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
		if (paginatedListsError) return next(paginatedListsError);

		const { docs, ...pagination } = paginatedLists;

		return res.status(httpStatus.OK).json(
			compoundResponse({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
	getSingleList: async (req: Request, res: Response, next: NextFunction) => {
		const { list: listIdentifier } = req.params;
		const [listError, list] = await to(
			List.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: listIdentifier },
					...(listIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: listIdentifier }] : []),
				],
			})
		);
		if (listError) return next(listError);
		if (!list) return next();

		res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, entities: { data: list } }));
	},
	updateSingleList: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.stringify(validationErrors.mapped()));
			return next(compoundResponse({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { list: listIdentifier } = req.params;

		// eslint-disable-next-line prefer-const
		let [listError, list] = await to(
			List.findOneAndUpdate(
				{
					user: req?.user?._id || "",
					$or: [
						{ slug: listIdentifier },
						...(listIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: listIdentifier }] : []),
					],
				},
				{ ...(req?.body || {}) },
				{ new: true }
			)
		);
		if (listError) return next(listError);
		if (!list) return next();

		req.flash("success", "successfully updated.");
		res.status(httpStatus.OK).json(
			compoundResponse({ status: httpStatus.OK, entities: { data: list }, flashes: req.flash() })
		);
	},
	deleteSingleList: async (req: Request, res: Response, next: NextFunction) => {
		const { list: listIdentifier } = req.params;

		const [listError, list] = await to(
			List.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: listIdentifier },
					...(listIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: listIdentifier }] : []),
				],
			})
		);
		if (listError) return next(listError);
		if (!list) return next();

		const [deleteListError] = await to(List.deleteOne({ _id: list?._id }));
		if (deleteListError) return next(deleteListError);

		req.flash("success", "Successfully Deleted.");
		res.status(httpStatus.OK).json(compoundResponse({ status: httpStatus.OK, flashes: req.flash() }));
	},
};

export default ListController;
