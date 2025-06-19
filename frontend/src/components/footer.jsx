import Box from "@mui/material/Box"
import Collapsible from "react-collapsible";

const Footer = (props) => {
    const { value } = props;

    console.debug("FOOTER", "value", value);

    return (
        <Box sx={{
            backgroundColor: 'rgb(1, 111, 157)',
            position: 'fixed',
            width: '100%',
            bottom: '0',
            color: 'white',
            textAlign: 'center',
            zIndex: 1000,
        }}>
            <Collapsible trigger="&#9662; NOTES &#9662;">
                <Box sx={{
                    backgroundColor: 'whitesmoke',
                    color: 'rgb(1, 111, 157)',
                    p: 2,
                }}>
                    Welcome to Certificate Tools!
                    <br />
                    This application helps you manage SSL certificates.
                    <br />
                    More features will be available soon.
                    <br />
                </Box>
            </Collapsible>
        </Box>
    )
}

export default Footer;