import multer, { MulterError } from "multer";
import multerS3 from "multer-s3";
import { v6 as uuid } from "uuid";
import { fileTypeFromFile } from "file-type";
import { s3Client } from "@/config/aws_config";
import Config from "@/config/config";

const allowedImage = ["image/png", "image/jpeg"];

const uploadMiddleware = multer({
  fileFilter: async (req, file, cb) => {
    const fileType = await fileTypeFromFile(file.originalname)!;
    if (fileType?.mime && allowedImage.includes(fileType?.mime)) {
      cb(null, true);
    } else {
      cb(
        new MulterError(
          "LIMIT_UNEXPECTED_FILE",
          "Limited file types allowed - only .png, .jpeg"
        )
      );
    }
  },
  limits: {
    fileSize: 1024 * 1024 * 8, // 8MB
  },
  storage: multerS3({
    s3: s3Client,
    bucket: Config.AWS_S3_BUCKET,
    acl: "public-read",
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname });
    },
    key: async function (req, file, cb) {
      const fileType = await fileTypeFromFile(file.originalname)!;
      if (fileType?.mime && allowedImage.includes(fileType?.mime)) {
        cb(
          null,
          `${uuid()}/${Date.now().toString()}-${uuid()}.${fileType.ext}`
        );
      } else {
        cb(
          new MulterError(
            "LIMIT_UNEXPECTED_FILE",
            "Limited file types allowed - only .png, .jpeg"
          )
        );
      }
    },
  }),
});

export { uploadMiddleware };
