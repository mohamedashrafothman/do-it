import allowMethods from "allow-methods";
import { Router } from "express";
import { default as listsController } from "../../controllers/lists";

const router = Router();

// Endpoints
router
	.route("/")
	.all(allowMethods(["post", "get"]))
	.post(listsController.validator("store"), listsController.postSingleList)
	.get(listsController.getLists);
router
	.route("/deleted")
	.all(allowMethods(["get"]))
	.get(listsController.getDeletedLists);
router
	.route("/:list")
	.all(allowMethods(["get", "patch", "delete"]))
	.get(listsController.getSingleList)
	.patch(listsController.validator("update"), listsController.updateSingleList)
	.delete(listsController.deleteSingleList);
router
	.route("/:list/restore")
	.all(allowMethods(["patch"]))
	.patch(listsController.restoreSingleList);

// Exporting router
export default router;
