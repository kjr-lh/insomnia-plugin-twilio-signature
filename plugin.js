const crypto = require('crypto')
const querystring = require('querystring');

function getExpectedTwilioSignature(authToken, url, params, body) {
  const [endpoint, urlParams] = url.split('?');
  const allParams = {
    ...querystring.parse(urlParams),
    ...params.reduce((o, { name, value }) => {
      o[name] = value;
      return o;
    }, {})
  }
  // Insomnia sorts parameters before sending
  // TODO: Check if the new request.getBody() method provides params already sorted
  const qsOrderedParams = Object.keys(allParams)
    .sort()
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(allParams[k])}`)
    .join('&');
  let data = `${endpoint}?${qsOrderedParams}`;
  if (body) {
    data = Object.keys(JSON.parse(body))
      .sort()
      .reduce((acc, key) => acc + key + body[key], data);
  }

  return crypto
    .createHmac('sha1', authToken)
    .update(Buffer.from(data, 'utf-8'))
    .digest('base64');
}

module.exports.requestHooks = [function (context) {
  const twilioAuthToken = context.request.getEnvironmentVariable('twilio_auth_token');

  if (!twilioAuthToken) {
    console.log('No {{twilio_auth_token}} set in this environment.');
    return;
  }

  const twilioSignature = getExpectedTwilioSignature(
    twilioAuthToken,
    context.request.getUrl(),
    context.request.getParameters(),
    // TODO: use request.getBody() to ge access to form data when new version is released.
    context.request.getBodyText(),
  );

  context.request.setHeader('X-Twilio-Signature', twilioSignature)
}];
