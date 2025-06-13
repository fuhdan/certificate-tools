const API_BASE_URL = process.env.REACT_APP_API_URL || '';

export const checkServerStatus = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`);
    return response.ok;
  } catch (error) {
    return false;
  }
};

export const parseCertificate = async (content, privateKey = '', chain = '') => {
  const requestBody = { content };
  
  // Add private key if provided
  if (privateKey.trim()) {
    requestBody.privateKey = privateKey;
  }

  // Add certificate chain if provided
  if (chain.trim()) {
    requestBody.chain = chain;
  }

  const response = await fetch(`${API_BASE_URL}/api/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody)
  });

  const data = await response.json();
  
  if (data.error) {
    throw new Error(data.error);
  }

  return data;
};