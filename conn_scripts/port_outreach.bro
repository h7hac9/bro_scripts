# 端口外联检测脚本

@load base/frameworks/notice
@load base/frameworks/sumstats

module OUTREACH;

export {
    redef enum NOTICE::Type += {
        Port_Outreach,
    };

    const number: double = 40.0 &redef;

    const epoch = 1min &redef;
}

event bro_init()
{
    local r1: SumStats::Reducer = [$stream="conn.port.outreach", $apply=set(SumStats::SUM)];
    SumStats::create([$name="port-outreach",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $threshold = count,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                            return result["conn.port.outreach"]$sum;
                      },
                      $threshold=sqli_requests_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                            local r = result["conn.port.outreach"];
                            NOTICE([$note=Port_Outreach,
                                    $msg="主机频繁连接某一端口",
                                    $email_body_sections=vector(format_sqli_samples(r$samples)),
                                    $src=key$host,  
                                    $identifier=cat(key$host)]);
                      }]);
    
}

event connection_established(c: connection) &priority=5
{
    SumStats::observe("conn.port.outreach", [$host=c$id$orig_h];
}