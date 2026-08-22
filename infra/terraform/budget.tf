# =============================================================================
# budget.tf — 비용 알람
# =============================================================================
# 사람은 반드시 잊습니다. 자동화가 답입니다.

resource "aws_budgets_budget" "monthly" {
  name         = "kisia-net1-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # 절반 썼을 때 — "속도를 보자"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_emails
  }

  # 대부분 썼을 때 — "이제 아껴야 함"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_emails
  }

  # 이대로 가면 초과 예상 — "지금 멈춰라"
  # 실제로 다 쓴 다음에 알려주면 이미 늦습니다.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_emails
  }
}
