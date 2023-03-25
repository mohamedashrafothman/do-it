import allowMethods from "allow-methods";
import { ensureLoggedIn } from "connect-ensure-login";
import { Router } from "express";
import { default as indexController } from "../../../controllers/index";

const router = Router();

// Breakpoints
router
	.route("/locale/:locale")
	.all(allowMethods(["get"]))
	.get(indexController.changeLocale);
router
	.route("/")
	.all(allowMethods(["get"]), ensureLoggedIn("/dashboard/auth/login"))
	.get(indexController.getWebIndex);

// Exporting router
export default router;
