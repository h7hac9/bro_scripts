## 端口外联检测脚本

##说明：在使用时请将中文注释删除再导入

@load base/frameworks/notice
@load base/frameworks/sumstats

module OUTREACH;

export {
    redef enum Notice::Type += {
        Port_Outreach
    };

    ## 主要用于sumstats框架向notice框架中传递的参数，可以显示在notice.log日志文件中
    redef record SumStats::Key += {
        p: port &optional;
        src_host: addr &optional;
    };

    const number: double = 15.0 &redef;
    
    const epoch = 0.5min &redef;
}

event bro_init()
{
    local r1: SumStats::Reducer = [$stream="conn.port.outreach", $apply=set(SumStats::SUM)];
    SumStats::create([$name="port-outreach",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $threshold = number,
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                            return result["conn.port.outreach"]$sum;
                      },
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                            local r = result["conn.port.outreach"];
                            NOTICE([$note=Port_Outreach,
                                    $msg="主机频繁连接某一端口",
                                    $dst=key$host,
                                    $src=key$src_host,
                                    $p=key$p,
                                    $identifier=cat(key$host)]);
                      }]);
}

event connection_state_remove(c: connection) &priority=5
{
    SumStats::observe("conn.port.outreach", SumStats::Key($src_host=c$id$orig_h,$host=c$id$resp_h,$p=c$id$resp_p), SumStats::Observation($num=1));
}