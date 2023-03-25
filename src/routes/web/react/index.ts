import allowMethods from "allow-methods";
import { Router } from "express";
import { default as indexController } from "../../../controllers/index";

const router = Router();

// Breakpoints
router
	.route("/")
	.all(allowMethods(["get"]))
	.get(indexController.getReactIndex);

// Exporting router
export default router;
