import allowMethods from "allow-methods";
import { Router } from "express";
import passport from "passport";
import authRouter from "./auth";
import usersRouter from "./users";

const router = Router();

// Breakpoints
router
	.route("/protected")
	.all(allowMethods(["get"]), passport.authenticate("jwt", { session: false }))
	.get((_req, res) => res.status(200).json({ message: "you are authorized" }));

// Nested routes
router.use("/auth", authRouter);
router.use("/users", passport.authenticate("jwt", { session: false }), usersRouter);

// Exporting router
export default router;
