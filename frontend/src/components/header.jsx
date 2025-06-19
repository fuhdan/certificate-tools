import Box from "@mui/material/Box"
import ypsomedLogo1 from '../assets/ypsomedLogo1.png'
import Button from "@mui/material/Button";
import {useState} from "react";

const Header = ({parentCallback}) => {
    const [isSignedIn, setIsSignedIn] = useState(false);
    const [userName, setUserName] = useState("Demo User");

    const handleSignIn = () => {
        console.log("Demo sign in clicked - making user superuser");
        setIsSignedIn(true);
        setUserName("Demo User (Superuser)");
        
        // Set as superuser
        sessionStorage.setItem("isAuthorized", String(false));
        sessionStorage.setItem("isSuperuser", String(true));
        
        // Notify parent
        const roleDataJson = {
            isSuperuser: true,
            isAuthorized: false,
        }
        console.log("HEADER: Calling parentCallback with", roleDataJson);
        parentCallback(roleDataJson);
    };

    const handleSignOut = () => {
        console.log("Demo sign out clicked");
        setIsSignedIn(false);
        setUserName("Demo User");
        
        // Clear session storage
        sessionStorage.setItem("isAuthorized", String(false));
        sessionStorage.setItem("isSuperuser", String(false));
        
        // Notify parent
        const roleDataJson = {
            isSuperuser: false,
            isAuthorized: false,
        }
        parentCallback(roleDataJson);
    };

    return (
        <Box sx={{
            display: 'flex',
            flexDirection: 'row',
            alignItems: 'center',
            p: 1,
            backgroundColor: 'rgb(1, 111, 157)',
        }}>
            <Box sx={{
                width: '20%'
            }}>
                <img 
                    src={ypsomedLogo1} 
                    alt="Logo" 
                    style={{maxHeight: '50px'}}
                    onError={(e) => {
                        // Fallback if logo is missing
                        e.target.style.display = 'none';
                        e.target.nextSibling.style.display = 'block';
                    }}
                />
                <div 
                    style={{
                        display: 'none',
                        color: 'white',
                        fontWeight: 'bold',
                        fontSize: '18px'
                    }}
                >
                    Certificate Tools
                </div>
            </Box>
            <Box sx={{
                display: 'flex',
                flexDirection: 'row',
                alignItems: 'center',
                justifyContent: 'right',
                width: '80%',
            }}
            >
                <Box>
                    {!isSignedIn ? (
                        <Button
                            variant="contained"
                            onClick={handleSignIn}
                            sx={{
                                backgroundColor: 'white',
                                color: 'black',
                                m: 1,
                                borderRadius: '5px',
                            }}
                        >
                            SIGN IN (DEMO)
                        </Button>
                    ) : (
                        <Button
                            variant="contained"
                            onClick={handleSignOut}
                            sx={{
                                backgroundColor: 'gold',
                                color: 'black',
                                m: 1,
                                borderRadius: '100px',
                            }}
                        >
                            {userName}
                        </Button>
                    )}
                </Box>
            </Box>
        </Box>
    )
}

export default Header;