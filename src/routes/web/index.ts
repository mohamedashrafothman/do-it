import { Router } from "express";
import dashboardRouter from "./dashboard";
import reactRouter from "./react";

const router = Router();

// Nested routes
router.use("/dashboard", dashboardRouter);
router.use(/^\/((?!api|dashboard).)*$/, reactRouter);

// Exporting router
export default router;
