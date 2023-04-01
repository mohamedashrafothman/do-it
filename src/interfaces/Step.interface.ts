import { Types } from "mongoose";

export default interface Step {
	user: Types.ObjectId;
	title: string;
	dueDate?: Date;
	completed: boolean;
	orderInList: number;
	totalRepeatCount?: number;
	currentRepeatCount?: number;
}
