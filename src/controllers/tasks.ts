import to from "await-to-js";
import { NextFunction, Request, Response } from "express";
import { body, validationResult } from "express-validator";
import httpStatus from "http-status";
import Step from "../models/Step";
import Task from "../models/Task";
import { formatResponseObject } from "../utils/helpers";

const TaskController = {
	validator: (method: string) => {
		switch (method) {
			case "store":
			case "update":
				return [
					body("name").notEmpty().withMessage("You must supply a name!").trim().escape(),
					body("list").notEmpty().withMessage("You must supply a list!"),
					body("steps")
						.notEmpty()
						.withMessage("You must supply a step list!")
						.isArray()
						.withMessage("Steps must be in array format!"),
					body("steps.*.title").notEmpty().withMessage("You must supply a step title!").trim().escape(),
					body("steps.*.orderInList").notEmpty().withMessage("You must supply a step order in list!"),
				];
			default:
				return [];
		}
	},
	postSingleTask: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.parse(JSON.stringify(validationErrors.array({ onlyFirstError: true }))));
			return next(formatResponseObject({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { steps = [], ...body } = req.body || {};

		const [createdStepsError, createdSteps] = await to(
			Step.create([...(steps?.map((step: object) => ({ ...(step || {}), user: req?.user?._id || "" })) || [])])
		);
		if (createdStepsError) return next(createdStepsError);

		const [createdTaskError, createdTask] = await to(
			Task.create({
				...(body || {}),
				steps: [...(createdSteps?.map(({ _id }) => _id) || [])],
				user: req?.user?._id || "",
			})
		);
		if (createdTaskError) return next(createdTaskError);

		req.flash("success", "Successfully created!");
		res.status(httpStatus.CREATED).json(
			formatResponseObject({
				status: httpStatus.CREATED,
				entities: { data: { task: createdTask } },
				flashes: req.flash(),
			})
		);
	},
	getTasks: async (req: Request, res: Response, next: NextFunction) => {
		const { q, ...query } = req.query;
		const querySearchFields = ["name"];
		const sort = [
			{ name: "Name A-Z", value: { name: 1 } },
			{ name: "Name Z-A", value: { name: -1 } },
			{ name: "Created Date Ascending", value: { created_at: 1 } },
			{ name: "Created Date Descending", value: { created_at: -1 } },
		];

		const [paginatedTasksError, paginatedTasks] = await to(
			Task.paginate(
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
		if (paginatedTasksError) return next(paginatedTasksError);

		const { docs, ...pagination } = paginatedTasks;

		return res.status(httpStatus.OK).json(
			formatResponseObject({
				status: httpStatus.OK,
				entities: { data: [...(docs || [])], meta: { pagination, sort } },
			})
		);
	},
	getSingleTask: async (req: Request, res: Response, next: NextFunction) => {
		const { task: taskIdentifier } = req.params;
		const [taskError, task] = await to(
			Task.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: taskIdentifier },
					...(taskIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: taskIdentifier }] : []),
				],
			})
		);
		if (taskError) return next(taskError);
		if (!task) return next();

		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, entities: { data: task } }));
	},
	updateSingleTask: async (req: Request, res: Response, next: NextFunction) => {
		const validationErrors = validationResult(req);
		if (!validationErrors.isEmpty()) {
			req.flash("danger", JSON.parse(JSON.stringify(validationErrors.array({ onlyFirstError: true }))));
			return next(formatResponseObject({ status: httpStatus.UNPROCESSABLE_ENTITY, flashes: req.flash() }));
		}

		const { task: taskIdentifier } = req.params;

		// eslint-disable-next-line prefer-const
		let [taskError, task] = await to(
			Task.findOneAndUpdate(
				{
					user: req?.user?._id || "",
					$or: [
						{ slug: taskIdentifier },
						...(taskIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: taskIdentifier }] : []),
					],
				},
				{ ...(req?.body || {}) },
				{ new: true }
			)
		);
		if (taskError) return next(taskError);
		if (!task) return next();

		req.flash("success", "successfully updated.");
		res.status(httpStatus.OK).json(
			formatResponseObject({ status: httpStatus.OK, entities: { data: task }, flashes: req.flash() })
		);
	},
	deleteSingleTask: async (req: Request, res: Response, next: NextFunction) => {
		const { task: taskIdentifier } = req.params;

		const [taskError, task] = await to(
			Task.findOne({
				user: req?.user?._id || "",
				$or: [
					{ slug: taskIdentifier },
					...(taskIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: taskIdentifier }] : []),
				],
			})
		);
		if (taskError) return next(taskError);
		if (!task) return next();

		const [deleteTaskError] = await to(Task.deleteById(task?._id));
		if (deleteTaskError) return next(deleteTaskError);

		req.flash("success", "Successfully Deleted.");
		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, flashes: req.flash() }));
	},
	restoreSingleTask: async (req: Request, res: Response, next: NextFunction) => {
		const { task: taskIdentifier } = req.params;

		const [taskError, task] = await to(
			Task.findOneWithDeleted({
				user: req?.user?._id || "",
				$or: [
					{ slug: taskIdentifier },
					...(taskIdentifier.match(/^[0-9a-fA-F]{24}$/) ? [{ _id: taskIdentifier }] : []),
				],
			})
		);
		if (taskError) return next(taskError);
		if (!task) return next();

		const [restoreTaskError] = await to(Task.restore());
		if (restoreTaskError) return next(restoreTaskError);

		req.flash("success", "Successfully Restored.");
		res.status(httpStatus.OK).json(formatResponseObject({ status: httpStatus.OK, flashes: req.flash() }));
	},
};

export default TaskController;
