import allowMethods from "allow-methods";
import { Router } from "express";
import { default as usersController } from "../../controllers/users";

const router = Router();

// Breakpoints
router
	.route("/")
	.all(allowMethods(["get"]))
	.get(usersController.getUsers);
router
	.route("/me")
	.all(allowMethods(["get"]))
	.get(usersController.getCurrentAuthenticatedUser);
router
	.route("/:user")
	.all(allowMethods(["get", "patch", "delete"]))
	.get(usersController.getSingleUser)
	.patch(usersController.validator("update"), usersController.updateSingleUser)
	.delete(usersController.deleteSingleUser);

// Exporting router
export default router;
