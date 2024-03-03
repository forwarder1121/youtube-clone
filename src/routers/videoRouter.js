import express from "express";
import {
    getEdit,
    postEdit,
    watch,
    getUpload,
    postUpload,
    deleteVideo,
} from "../controllers/videoController";
import { protectorMiddleware } from "../middlewares";
const videoRouter = express.Router();

videoRouter.get("/:id([0-9a-f]{24})", watch);
//비디오 소유주만 CRUD 가능
videoRouter
    .route("/:id([0-9a-f]{24})/edit")
    .all(protectorMiddleware)
    .get(getEdit)
    .post(postEdit);
videoRouter
    .route("/:id([0-9a-f]{24})/delete")
    .all(protectorMiddleware)
    .get(deleteVideo);

videoRouter
    .route("/upload")
    .all(protectorMiddleware)
    .get(getUpload)
    .post(postUpload);

export default videoRouter;
