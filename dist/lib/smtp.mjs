import { createTransport } from "nodemailer";
export function createSmtpSender(createTransportFn = createTransport) {
    if (typeof createTransportFn !== "function")
        throw new Error("rightout_smtp_factory_invalid");
    return async function sendSmtpMail({ transport, message, signal }) {
        if (signal?.aborted)
            throw new Error("rightout_removal_cancelled_before_transport");
        const client = createTransportFn({
            host: transport.host,
            port: transport.port,
            secure: transport.secure,
            requireTLS: !transport.secure,
            auth: { user: transport.username, pass: transport.password },
            connectionTimeout: 10_000,
            greetingTimeout: 10_000,
            socketTimeout: 20_000,
            disableFileAccess: true,
            disableUrlAccess: true,
            tls: { servername: transport.host, rejectUnauthorized: true, minVersion: "TLSv1.2" },
        });
        if (!client || typeof client.sendMail !== "function" || typeof client.close !== "function") {
            throw new Error("rightout_smtp_transport_invalid");
        }
        const close = () => {
            try {
                client.close();
            }
            catch {
                // Transport cleanup must not expose provider errors or override the sanitized send result.
            }
        };
        const abort = () => close();
        signal?.addEventListener("abort", abort, { once: true });
        try {
            if (signal?.aborted)
                throw new Error("rightout_removal_cancelled_before_transport");
            return await client.sendMail(message);
        }
        finally {
            signal?.removeEventListener("abort", abort);
            close();
        }
    };
}
