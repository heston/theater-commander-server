import * as admin from "firebase-admin";
import * as crypto from "crypto";
import {
  config,
  logger,
  runWith,
  Request,
  Response,
} from "firebase-functions";

admin.initializeApp(config().firebase);

const COLLECTION_NAME = "message";
const ON_MESSAGE = "on";
const OFF_MESSAGE = "off";


/**
 * Whether a request is authorized based on the given key.
 *
 * @param   {string}  key  The auth key to validate.
 *
 * @return  {boolean}
 */
function isAuthorized(key: string): boolean {
  const secretkey = process.env.IFTTT_SECRETKEY;

  // Fail closed if key is missing
  if (!secretkey) {
    logger.debug("No secret key provided.");
    return false;
  }

  try {
    return crypto.timingSafeEqual(
        Buffer.from(key, "utf8"),
        Buffer.from(secretkey, "utf8")
    );
  } catch (e) {
    return false;
  }
}

/**
 * Decorator that validates authentication ona request handler.
 *
 * @param   {Function}   fcn  Request handler function to decorate.
 *
 * @return  {Function}        Decorated function.
 */
function withAuth(fcn: (req: Request, res: Response) => void) {
  return function withAuthImpl(req: Request, res: Response) {
    // Get the auth token from the request, looking in the body and headers.
    const secretKey = (
      req.body.authentication ||
      req.header("authorization") ||
      ""
    );

    if (!isAuthorized(secretKey)) {
      res.status(401).send("Unauthorized");
      return;
    }

    fcn(req, res);
  };
}

/**
 * Write a command to the message collection.
 *
 * @param   {string}   command  The command the write: ON_MESSAGE or OFF_MESSAGE
 *
 * @return  {Promise<void>}     A promise for the database write.
 */
function writeMessage(command: string): Promise<void> {
  return admin.database().ref(COLLECTION_NAME).set(command);
}

/**
 * Request handler to send ON_MESSAGE.
 *
 * @param   {Request}  req  The request object.
 * @param   {Response}  res  The response object.
 */
const turnOn = withAuth((req, res) => {
  writeMessage(ON_MESSAGE)
      .then(() => res.status(200).send("OK"))
      .catch(() => res.status(503).send("Could not save command to database"));
});

/**
 * Request handler to send OFF_MESSAGE.
 *
 * @param   {Request}  req  The request object.
 * @param   {Response}  res  The response object.
 */
const turnOff = withAuth((req, res) => {
  writeMessage(OFF_MESSAGE)
      .then(() => res.status(200).send("OK"))
      .catch(() => res.status(503).send("Could not save command to database"));
});

exports.turnOn = runWith({secrets: ["IFTTT_SECRETKEY"]})
    .https.onRequest(turnOn);
exports.turnOff = runWith({secrets: ["IFTTT_SECRETKEY"]})
    .https.onRequest(turnOff);
