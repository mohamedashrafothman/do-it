import compression from "compression";
import flash from "connect-flash";
import timeout from "connect-timeout";
import cookieParser from "cookie-parser";
import cors from "cors";
import express, { Request, Response } from "express";
import helmet from "helmet";
import i18n from "i18n";
import methodOverride from "method-override";
import loggerToMongo from "mongo-morgan-ext";
import passport from "passport";
import path from "path";
import xss from "xss-clean";
import csrf from "./middlewares/csrf";
import { internalServerErrorHandler, notFoundErrorHandler } from "./middlewares/errorHandlers";
import locals from "./middlewares/locals";
import logger from "./middlewares/logger";
import queryParser from "./middlewares/queryParser";
import rateLimiter from "./middlewares/rateLimiter";
import session from "./middlewares/session";
import routes from "./routes";
import { normalizePort } from "./utils/helpers";
import vars from "./utils/vars";

// express application instance
const app = express();

// View engine setup
app.set("views", path.join(__dirname, "../views"));
app.set("view engine", "pug");

// Middlewares
app.set("port", normalizePort(vars.app.port));
app.set("url", vars.app.url);
app.set("x-powered-by", false);
app.set("trust proxy", true); // to get user IP
app.use("/public", express.static(path.join(__dirname, "../public/"))); // serving public files.
app.use("/storage", express.static(path.join(__dirname, "../public/storage/"))); // serving storage/multimedia files.
app.use(timeout("1m"));
app.use(logger);
app.use(express.json()); // parse body params and attache them to req.body
app.use(express.urlencoded({ extended: true })); // parse body params and attache them to req.body
app.use(queryParser); // A parser helps to parse req.query number, boolean, null, and undefined values.
app.use(cookieParser(vars.session.secret));
app.use(session);
app.use(passport.initialize()); // Passport.js middleware came after session's middleware.
app.use(passport.session()); // Passport.js middleware came after session's middleware.
app.use(methodOverride("_method")); // lets you use HTTP verbs in places where the client doesn't support it
app.use(helmet()); // secure apps by setting various HTTP headers
app.use(xss()); // sanitize user input in request body, params, and query.
app.use(cors({ origin: vars.cors.allowedOrigins })); // secure apps by setting various HTTP headers
app.use(compression()); // Gzip compressing can decrease the size of the response body.
app.use(csrf); // csrf protection MUST be defined after cookieParser and session middleware.
app.use(flash());
app.use(i18n.init); // i18n init parses req for language headers, cookies, etc.
// This would skip if HTTP request response is less than 399 i.e no errors.
app.use(loggerToMongo(vars.db.url, "logs", (req: Request, res: Response) => res.statusCode < 399));
app.use(locals);

// Routes
app.use("/", rateLimiter, routes);

// Error Handling
// Catch not found error and forward to error handler.
app.use(notFoundErrorHandler);

// Error handler, send stacktrace only during development.
app.use(internalServerErrorHandler);

// Exporting express app instance
export default app;
