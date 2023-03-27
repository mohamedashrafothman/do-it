import { Router } from "express";
import passport from "passport";
import authRouter from "./auth";
import labelsRouter from "./labels";
import usersRouter from "./users";

const router = Router();

// Nested routes
router.use("/auth", authRouter);
router.use("/users", passport.authenticate("jwt", { session: false }), usersRouter);
router.use("/labels", passport.authenticate("jwt", { session: false }), labelsRouter);

// Exporting router
export default router;
