import { Router } from "express";
import passport from "passport";
import authRouter from "./auth";
import labelsRouter from "./labels";
import listsRouter from "./lists";
import usersRouter from "./users";

const router = Router();

// Nested routes
router.use("/auth", authRouter);
router.use("/users", passport.authenticate("jwt", { session: false }), usersRouter);
router.use("/labels", passport.authenticate("jwt", { session: false }), labelsRouter);
router.use("/lists", passport.authenticate("jwt", { session: false }), listsRouter);

// Exporting router
export default router;
