@load base/frameworks/files
@load base/protocols/http

module HTTP_PostBody;

redef record HTTP::Info += {
    response_body: string &log &optional;
};

event log_response_data(f: fa_file, data:string)
{
    for(cid in f$conns)
    {
	local c: connection = f$conns[cid];
	if( ! c$http?$response_body )
	    c$http$response_body = "";
	
	c$http$response_body = c$http$response_body + data;
    }
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
{
    if( !is_orig && c?$http )
    {
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,[$stream_event=log_response_data]);
    }
}
