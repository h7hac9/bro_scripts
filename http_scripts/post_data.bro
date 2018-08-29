@load base/frameworks/files
@load base/protocols/http

module RESPONSE;

redef record HTTP::Info += {
    post_data: string &log &optional;
};

event log_post_data(f: fa_file, data:string)
{
    for(cid in f$conns)
    {
	local c: connection = f$conns[cid];
	if( ! c$http?$post_data )
	    c$http$post_data = "";
	
	c$http$post_data = c$http$post_data + data;
    }
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
    if( is_orig && c?$http && c$http?$method && c$http$method == "POST")
    {
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,[$stream_event=log_post_data]);
    }
}
