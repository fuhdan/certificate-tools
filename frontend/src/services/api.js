const API_BASE_URL = process.env.REACT_APP_API_URL || '';

export const checkServerStatus = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/api/health`);
    return response.ok;
  } catch (error) {
    return false;
  }
};

export const parseCertificate = async (content, privateKey = '', chain = '', password = '') => {
  const requestBody = { content };
  
  // Add private key if provided
  if (privateKey.trim()) {
    requestBody.privateKey = privateKey;
    
    // Add password if provided
    if (password.trim()) {
      requestBody.privateKeyPassword = password;
    }
  }

  // Add certificate chain if provided
  if (chain.trim()) {
    requestBody.chain = chain;
  }

  console.log('API Request /api/parse:', {
    content: content ? `${content.length} chars` : 'empty',
    privateKey: privateKey ? `${privateKey.length} chars` : 'none',
    password: password ? 'provided' : 'none',
    chain: chain ? `${chain.length} chars` : 'none'
  });

  const response = await fetch(`${API_BASE_URL}/api/parse`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestBody)
  });

  const data = await response.json();
  
  console.log('API Response:', {
    status: response.status,
    type: data.type,
    keyValidation: data.privateKeyValidation ? 
      `${data.privateKeyValidation.keyPairValid ? '✅' : '❌'} ${data.privateKeyValidation.details?.error || 'OK'}` : 'none',
    chainValidation: data.chainValidation ? 
      `${data.chainValidation.chainValid ? '✅' : '❌'} (${data.chainValidation.chainLength} certs)` : 'none'
  });
  
  if (data.error) {
    throw new Error(data.error);
  }

  return data;
};