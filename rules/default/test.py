from stream_alert.rule_processor.rules_engine import StreamRules
rule = StreamRules.rule
@rule(logs=['Test'],outputs=['slack:Venu'])
def always_accept_rule(record):          
        return True 
