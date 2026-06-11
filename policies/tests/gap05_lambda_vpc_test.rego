package compliance.soc2.gap05_lambda_vpc

import rego.v1

# --- PASSING: Lambda has vpc_config with subnets and SGs ---
test_lambda_in_vpc_passes if {
	count(deny) == 0 with input as {
		"resource_changes": [{
			"address": "aws_lambda_function.intake",
			"type": "aws_lambda_function",
			"change": {"after": {"vpc_config": [{"subnet_ids": ["subnet-abc", "subnet-def"], "security_group_ids": ["sg-abc"]}]}},
		}],
	}
}

# --- FAILING: Lambda has no vpc_config ---
test_lambda_no_vpc_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_lambda_function.intake",
			"type": "aws_lambda_function",
			"change": {"after": {"vpc_config": []}},
		}],
	}
}

# --- FAILING: Lambda vpc_config has empty subnet list ---
test_lambda_empty_subnets_denied if {
	count(deny) > 0 with input as {
		"resource_changes": [{
			"address": "aws_lambda_function.intake",
			"type": "aws_lambda_function",
			"change": {"after": {"vpc_config": [{"subnet_ids": [], "security_group_ids": ["sg-abc"]}]}},
		}],
	}
}
