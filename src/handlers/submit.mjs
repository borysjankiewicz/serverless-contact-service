import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";

const ses = new SESClient({ region: process.env.AWS_REGION || "eu-west-1" });

// Prosta funkcja sanitizacji (Security)
const esc = (text) => text ? text.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[m]) : '';

export const handler = async (event) => {
    // 1. CORS: Odbijamy Origin nadawcy (działa na localhost i produkcji)
    const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": event.headers?.origin || event.headers?.Origin || "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,X-Requested-With",
    };

    // 2. PREFLIGHT: Szybki zwrot dla zapytania OPTIONS
    if ((event.requestContext?.http?.method || event.httpMethod) === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        // 3. LOGIKA: Parsowanie i walidacja w jednym bloku
        const body = JSON.parse(event.body || "{}");
        const { name, email, subject, message, 'cf-turnstile-response': cfToken, privacy_policy } = body;

        if (!cfToken || !privacy_policy || !name || !email || !message) {
            return { statusCode: 422, headers, body: JSON.stringify({ success: false, error: "Uzupełnij wszystkie pola i zgody." }) };
        }

        // 4. CLOUDFLARE: Weryfikacja
        const formData = new URLSearchParams();
        formData.append('secret', process.env.CLOUDFLARE_SECRET_KEY);
        formData.append('response', cfToken);
        
        const cfRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: formData });
        const cfData = await cfRes.json();
        
        if (!cfData.success) {
            console.warn("Captcha fail:", cfData); // Logujemy tylko, jak coś pójdzie nie tak
            return { statusCode: 403, headers, body: JSON.stringify({ success: false, error: "Weryfikacja nieudana." }) };
        }

        // 5. SES: Wysyłka maila
        const prefix = process.env.ENV_TYPE === 'dev' ? '[DEV] ' : '';
        const finalSubject = `${prefix}[Kontakt] ${esc(subject || name)}`;

        await ses.send(new SendEmailCommand({
            Source: process.env.SENDER_EMAIL,
            Destination: { ToAddresses: [process.env.RECIPIENT_EMAIL] },
            ReplyToAddresses: [email],
            Message: {
                Subject: { Data: finalSubject },
                Body: { 
                    Html: { Data: `<h2>Wiadomość</h2><p>Od: ${esc(name)} (${esc(email)})</p><hr><p>${esc(message).replace(/\n/g, '<br>')}</p>` },
                    Text: { Data: message } 
                }
            }
        }));

        return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: "Wysłano!" }) };

    } catch (error) {
        console.error("Handler Error:", error);
        // Zawsze zwracamy headers CORS, żeby frontend widział błąd
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, error: "Błąd serwera." }) };
    }
};
