import allowMethods from "allow-methods";
import { Router } from "express";
import { default as labelsController } from "../../controllers/labels";

const router = Router();

// Endpoints
router
	.route("/")
	.all(allowMethods(["post", "get"]))
	.post(labelsController.validator("store"), labelsController.postSingleLabel)
	.get(labelsController.getLabels);
router
	.route("/deleted")
	.all(allowMethods(["get"]))
	.get(labelsController.getDeletedLabels);
router
	.route("/:label")
	.all(allowMethods(["get", "patch", "delete"]))
	.get(labelsController.getSingleLabel)
	.patch(labelsController.validator("update"), labelsController.updateSingleLabel)
	.delete(labelsController.deleteSingleLabel);
router
	.route("/:label/restore")
	.all(allowMethods(["patch"]))
	.patch(labelsController.restoreSingleLabel);

// Exporting router
export default router;
