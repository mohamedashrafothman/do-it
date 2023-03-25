import { Router } from "express";
import apiHeaders from "../middlewares/apiHeaders";
import apiRouter from "./api";
import webRouter from "./web";

const router = Router();

// Nested routes
router.use("/api", apiHeaders, apiRouter);
router.use("/", webRouter);

// Exporting router
export default router;
