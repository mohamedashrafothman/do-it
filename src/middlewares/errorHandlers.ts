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
			{
				status = httpStatus.INTERNAL_SERVER_ERROR,
				isWebView = undefined,
				message = "Whoops, something went wrong!",
				...err
			},
			req: Request,
			res: Response,
			// eslint-disable-next-line @typescript-eslint/no-unused-vars
			_next: NextFunction
			// eslint-disable-next-line no-mixed-spaces-and-tabs
	  ) =>
			res.format({
				json: () => {
					if (!isWebView) req.flash("danger", message);
					res.status(status).json({
						...(isWebView
							? { status, ...err }
							: compoundResponse({ status, flashes: req.flash(), ...err })),
						isWebView: undefined,
					});
				},
				html: () => {
					// Set locals, only providing error in development
					res.locals.message = message || err.error.message || "";
					res.locals.error = { status, message, ...err };

					// Render the error page
					res.status(status).render(`dashboard/pages/errors/${status}`);
				},
			});

export { internalServerErrorHandler, notFoundErrorHandler };
