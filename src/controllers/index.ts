import { Request, Response } from "express";
import i18n from "i18n";

const IndexController = {
	changeLocale: (req: Request, res: Response) => {
		i18n.setLocale(res, req.params.locale, true);
		res.cookie("locale", req.params.locale);
		res.redirect("back");
	},
	getWebIndex: (_req: Request, res: Response) =>
		res.render("dashboard/index", { pageTitle: "Admin Dashboard", title: "Admin Dashboard" }),
	getReactIndex: (_req: Request, res: Response) =>
		res.render("react/index", { pageTitle: "React application", title: "React Application" }),
};

export default IndexController;
