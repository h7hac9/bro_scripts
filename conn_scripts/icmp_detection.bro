@load base/frameworks/notice
@load base/frameworks/sumstats


event connection_state_remove(c: connection) &priority=5
{
    print(c);
}