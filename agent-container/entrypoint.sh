sed s/kenna_api_key/$kenna_api_key/g /etc/kenna-agent/kenna-agent.toml > kenna-agent-temp.toml
kenna-agent check --config kenna-agent-temp.toml
rm kenna-agent-temp.toml