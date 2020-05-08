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
  let data = endpoint;
  if (qsOrderedParams.length) {
    data = `${data}?${qsOrderedParams}`;
  }
  console.log(data);
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

module.exports.requestHooks = [async function (context) {
  if (!context.request.hasHeader('X-Twilio-Signature')) {
    return;
  }
  // const twilioAuthToken = context.request.getEnvironmentVariable('twilio_auth_token');
  const twilioAuthToken = await context.store.getItem('TwilioAuthToken');

  if (!twilioAuthToken) {
    console.log('TwilioSignature not configured.');
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

async function run(context, TwilioAuthToken) {
  if (!TwilioAuthToken) {
    return 'Missing TwilioAuthToken';
  }
  await context.store.setItem('TwilioAuthToken', TwilioAuthToken);

  console.log('TwilioSignature run.');

  return 'X-Twilio-Signature';
}

module.exports.templateTags = [{
  name: 'TwilioSignature',
  displayName: 'TwilioSignature',
  description: 'Insomnia Plugin to calculate Twilio Signature for your request.',
  args: [
    {
      displayName: 'TwilioAuthToken',
      type: 'string',
      validate: arg => (arg ? '' : 'Required')
    },
  ],
  run
}];
