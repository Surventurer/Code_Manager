const { getAllSnippets } = require('./db');

exports.handler = async function(event, context) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  try {
    const snippets = await getAllSnippets();
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(snippets)
    };
  } catch (error) {
    console.error('Error reading database:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to read database', details: error.message })
    };
  }
};
