import errorHandler from "errorhandler";
import { NextFunction, Request, Response } from "express";
import createError from "http-errors";
import httpStatus from "http-status";
import { compoundResponse } from "../utils/helpers";
import vars from "../utils/vars";

const notFoundErrorHandler = (_req: Request, _res: Response, next: NextFunction) =>
	next(createError(404, "The resources you're looking for is Not found."));
const internalServerErrorHandler = !vars.isProduction
	? errorHandler({ log: false })
	: (
			{ status = httpStatus.INTERNAL_SERVER_ERROR, message: _message = "Whoops, something went wrong!", ...err },
			req: Request,
			res: Response,
			// eslint-disable-next-line @typescript-eslint/no-unused-vars
			_next: NextFunction
			// eslint-disable-next-line no-mixed-spaces-and-tabs
	  ) => res.status(status).json(compoundResponse({ status, flashes: req.flash(), ...err }));

export { internalServerErrorHandler, notFoundErrorHandler };
