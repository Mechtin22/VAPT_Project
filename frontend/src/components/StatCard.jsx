function StatCard({ title, value, subtitle, icon: Icon }) {
    return (
        <div className="stat-card">

            <div className="stat-top">

                <div className="stat-icon">
                    {Icon && <Icon size={22} />}
                </div>

                <span>{subtitle}</span>

            </div>

            <h2>{value}</h2>

            <p>{title}</p>

        </div>
    );
}

export default StatCard;