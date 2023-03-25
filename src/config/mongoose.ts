import chalk from "chalk";
import mongoose from "mongoose";
import mongoosePagination from "mongoose-paginate-v2";
import vars from "../utils/vars";

mongoose.Promise = global.Promise;
mongoose.connect(vars.db.url, {});
mongoose.plugin(mongoosePagination);
mongoose.set("debug", !vars.isProduction);
mongoose.connection
	.once("open", () => console.log(chalk.blue("✅  Connected to the database")))
	.on("error", (error) => {
		console.error(error);
		console.log(`⛔️  ${chalk.red("MongoDB connection error")}.\n Please make sure MongoDB server is running.`);
		process.exit();
	});
