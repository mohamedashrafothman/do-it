import allowMethods from "allow-methods";
import { Router } from "express";
import { default as tasksController } from "../../controllers/tasks";

const router = Router();

// Endpoints
router
	.route("/")
	.all(allowMethods(["post", "get"]))
	.post(tasksController.validator("store"), tasksController.postSingleTask)
	.get(tasksController.getTasks);
router
	.route("/:task")
	.all(allowMethods(["get", "patch", "delete"]))
	.get(tasksController.getSingleTask)
	.patch(tasksController.validator("update"), tasksController.updateSingleTask)
	.delete(tasksController.deleteSingleTask);
router
	.route("/:task/restore")
	.all(allowMethods(["patch"]))
	.patch(tasksController.restoreSingleTask);

// Exporting router
export default router;
