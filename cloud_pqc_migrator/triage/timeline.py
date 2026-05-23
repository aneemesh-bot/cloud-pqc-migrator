from __future__ import annotations

from datetime import date
from dateutil.relativedelta import relativedelta

Q_DAY = date(2030, 1, 1)


def compute_t_start(t_cover_months: int, t_proj_months: int) -> date:
    """
    T_start = T_q-day − T_cover − T_proj

    Returns the latest date by which a migration must begin to ensure
    data is protected before Q-Day arrives.
    """
    t_start = Q_DAY - relativedelta(months=t_cover_months + t_proj_months)
    return t_start


def default_t_start(is_internet_facing: bool, t_proj_months: int = 6) -> date:
    t_cover = 24 if is_internet_facing else 12
    return compute_t_start(t_cover, t_proj_months)
