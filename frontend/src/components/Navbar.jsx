import {
    Shield
} from "lucide-react";

function Navbar() {

    return (

        <header className="navbar">

            <div>

                <h1>
                    Vulnerability Assessment
                </h1>

                <p>
                    Controlled local security
                    testing environment
                </p>

            </div>

            <div className="navbar-right">

                <div className="connection">
                    <span></span>
                    Localhost
                </div>

                <div className="profile">
                    <Shield size={18} />
                    Security Team
                </div>

            </div>

        </header>
    );
}

export default Navbar;