
#include "control.h"
#include "management.h"

#include <vector>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

using namespace control;

// Short alias for this namespace
namespace pt = boost::property_tree;

// Called by a connection when it terminates to request tidy-up.
void service::close_me(connection* c)
{

    // Just puts the connection on a list to clear up.
    close_me_lock.lock();
    close_mes.push(c);
    close_me_lock.unlock();

}

// service body, handles connections.
void service::run()
{

    try {
	svr.bind(sp.port);
	svr.listen();
    } catch (std::exception& e) {
	std::cerr << "Failed to start control service: " 
		  << e.what() << std::endl;
	return;
    }

    while (running) {

	// Wait for connection.
	bool activ = svr.poll(1.0);

	if (activ) {

	    // Accept the connection
	    boost::shared_ptr<tcpip::stream_socket> cn = svr.accept();

	    // Spawn a connection thread.
	    connection* c = new connection(cn, d, *this, sp);
	    connections.push_back(c);
	    c->start();

	}

	// Tidy up any connections which need clearing up.
	close_me_lock.lock();
	while (!close_mes.empty()) {

	    // Wait for thread to close.
	    close_mes.front()->join();

	    // Delete resource.
	    delete close_mes.front();
	    connections.remove(close_mes.front());

	    close_mes.pop();
	}
	close_me_lock.unlock();

    }

    // Signal all connections to close
    for(std::list<connection*>::iterator it = connections.begin();
	it != connections.end();
	it++)
	(*it)->stop();

    // Now wait for threads, and delete.
    for(std::list<connection*>::iterator it = connections.begin();
	it != connections.end();
	it++) {
	(*it)->join();
	delete *it;
    }

    svr.close();

}

// Return an OK response (should be status=200).
void connection::ok(int status, const std::string& msg)
{

    boost::property_tree::ptree root;
    root.put("status", status);
    root.put("message", msg);

    std::ostringstream buf;
    pt::write_json(buf, root, false);
    s->write(buf.str());

    std::cerr << "Reply: " << status << " " << msg << std::endl;
}

// Return an ERROR response (should be status=3xx or 5xx).
void connection::error(int status, const std::string& msg)
{

    boost::property_tree::ptree root;
    root.put("status", status);
    root.put("message", msg);

    std::ostringstream buf;
    pt::write_json(buf, root, false);
    s->write(buf.str());

    std::cerr << "Reply: " << status << " " << msg << std::endl;

}

// Return an OK response with payload (should be status=201).
void connection::response(int status, const std::string& msg,
			  const pt::ptree& resp)
{

    boost::property_tree::ptree root;
    root.put("status", status);
    root.put("message", msg);
    root.push_back(std::make_pair("response", resp));

    std::ostringstream buf;
    pt::write_json(buf, root, false);
    s->write(buf.str());

    std::cerr << "Reply: " << status << " " << msg << std::endl;
}

// 'endpoints' command.
void connection::cmd_endpoints()
{

    pt::ptree root;

    std::list<sender_info> si;
    d.get_endpoints(si);
    
    for(std::list<sender_info>::iterator it = si.begin();
	it != si.end();
	it++) {

	pt::ptree node;
	node.put("hostname", it->hostname);
	node.put("port", it->port);
	node.put("type", it->type);
	node.put("description", it->description);
	node.put("transport", it->transport);
	if (it->key != "")
	    node.put("key", it->key);
	if (it->certificate != "")
	    node.put("certificate", it->certificate);
	if (it->chain != "")
	    node.put("chain", it->chain);

	root.push_back(std::make_pair(it->hostname, node));

    }

    response(201, "Endpoints list.", root);

}

// 'interfaces' command.
void connection::cmd_interfaces()
{
    
    pt::ptree root;

    std::list<interface_info> ii;
    
    try {
	d.get_interfaces(ii);
    } catch (std::exception& e) {
	error(500, e.what());
	return;
    }
    
    for(std::list<interface_info>::iterator it = ii.begin();
	it != ii.end();
	it++) {

	pt::ptree node;
	node.put("interface", it->interface);
	if (it->delay != 0.0)
	    node.put("delay", it->delay);
	if (it->filter != "")
	    node.put("filter", it->filter);

	root.push_back(std::make_pair(it->interface, node));

    }

    response(201, "Interfaces list.", root);

}

// 'parameters' command.
void connection::cmd_parameters()
{

    pt::ptree root;

    std::map<std::string,std::string> p;
    d.get_parameters(p);
    
    for(std::map<std::string,std::string>::iterator it = p.begin();
	it != p.end();
	it++) {
	root.put(it->first, it->second);
    }

    response(201, "Parameters list.", root);

}

// 'targets' command.
void connection::cmd_targets()
{

    pt::ptree root;

    std::map<int, std::map<tcpip::ip4_address, std::string> > t4;
    std::map<int, std::map<tcpip::ip6_address, std::string> > t6;
    std::map<std::string, std::string> networks;
    
    d.get_targets(t4, t6, networks);

    for(std::map<int, std::map< tcpip::ip4_address, std::string> >::iterator it
	    = t4.begin();
	it != t4.end();
	it++) {

	for(std::map<tcpip::ip4_address, std::string>::iterator it2
		= it->second.begin();
	    it2 != it->second.end();
	    it2++) {

	    std::ostringstream buf2;

	    buf2 << it2->first << "/" << it->first;
	    
	    pt::ptree node;

	    node.put("liid", it2->second);
	    node.put("class", "ipv4");
	    node.put("address", buf2.str());
	    if (networks[it2->second] != "")
		node.put("network", networks[it2->second]);

	    root.push_back(std::make_pair(buf2.str(), node));

	}
    }
    
    for(std::map<int, std::map<tcpip::ip6_address, std::string> >::iterator it
	    = t6.begin();
	it != t6.end();
	it++) {
	
	for(std::map<tcpip::ip6_address, std::string>::iterator it2
		= it->second.begin();
	    it2 != it->second.end();
	    it2++) {

	    std::ostringstream buf2;

	    buf2 << it2->first << "/" << it->first;
	    
	    pt::ptree node;

	    node.put("liid", it2->second);
	    node.put("class", "ipv6");
	    node.put("address", buf2.str());
	    if (networks[it2->second] != "")
		node.put("network", networks[it2->second]);

	    root.push_back(std::make_pair(buf2.str(), node));

	}

    }
        
    response(201, "Targets list.", root);

}

// 'add_interface' command.
void connection::cmd_add_interface(const boost::property_tree::ptree& root)
{

    std::string iface;
    try {
	iface = root.get<std::string>("interface");
    } catch (...) {
	error(301, "interface attribute is required");
	return;
    }

    float delay = 0.0;

    try {
    	std::string d = root.get<std::string>("delay");
	std::istringstream buf(d);
	buf >> delay;
    } catch (...) {
	// Parameter is optional, ignore if not present.
    }

    std::string filter;

    try {
    	filter = root.get<std::string>("filter");
    } catch (...) {
	// Parameter is optional, ignore if not present.
    }
    
    try {
	d.add_interface(iface, filter, delay);
	ok(200, "Added interface.");
    } catch (std::exception& e) {
	error(500, e.what());
    }

}

// 'remove_interface' command.
void connection::cmd_remove_interface(const boost::property_tree::ptree& root)
{

    std::string iface;
    try {
	iface = root.get<std::string>("interface");
    } catch (...) {
	error(301, "interface attribute is required");
	return;
    }

    float delay = 0.0;

    try {
    	std::string d = root.get<std::string>("delay");
	std::istringstream buf(d);
	buf >> delay;
    } catch (...) {
	// Parameter is optional, ignore if not present.
    }

    std::string filter;

    try {
    	filter = root.get<std::string>("filter");
    } catch (...) {
	// Parameter is optional, ignore if not present.
    }
    
    try {
	d.add_interface(iface, filter, delay);
	ok(200, "Added interface.");
    } catch (std::exception& e) {
	error(500, e.what());
    }
    
    try {
	d.remove_interface(iface, filter, delay);
	ok(200, "Removed interface.");
    } catch (std::exception& e) {
	error(500, e.what());
    }

}

// 'add_target' command.
void connection::cmd_add_target(const boost::property_tree::ptree& root)
{
    
    std::string liid;
    std::string cls;
    std::string spec;
    try {
	liid = root.get<std::string>("liid");
	cls = root.get<std::string>("class");
	spec = root.get<std::string>("address");
    } catch (...) {
	error(301, "missing required attributes");
	return;
    }

    if (cls == "ipv4") {
	
	try {

	    tcpip::ip4_address a4;
	    unsigned int mask;
	    tcpip::ip4_address::parse(spec, a4, mask);

	    // FIXME: Can't control network parameter.
	    d.add_target(a4, mask, liid, "");

	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Added target.");
	return;
	
    }
    
    if (cls == "ipv6") {
	
	try {
	    unsigned int mask;
	    tcpip::ip6_address a6;
	    tcpip::ip6_address::parse(spec, a6, mask);
	    // FIXME: Can't control network parameter.
	    d.add_target(a6, mask, liid, "");
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Added target.");
	return;
	
    }
    
    error(301, "Address class not recognised.");
    
}

// 'remove_target' command.
void connection::cmd_remove_target(const boost::property_tree::ptree& root)
{

    std::string cls;
    std::string spec;
    try {
	cls = root.get<std::string>("class");
	spec = root.get<std::string>("address");
    } catch (...) {
	error(301, "missing required attributes");
	return;
    }

    if (cls == "ipv4") {
	
	try {
	    unsigned int mask;
	    tcpip::ip4_address a4;
	    tcpip::ip4_address::parse(spec, a4, mask);
	    d.remove_target(a4, mask);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}

	ok(200, "Removed target.");
	return;

    }

    if (cls == "ipv6") {
	
	try {
	    unsigned int mask;
	    tcpip::ip6_address a6;
	    tcpip::ip6_address::parse(spec, a6, mask);
	    d.remove_target(a6, mask);
	} catch (...) {
	    error(302, "Failed to parse address.");
	    return;
	}
	
	ok(200, "Remove target.");
	return;
	
    }
    
    error(301, "Address class not recognised.");
    
}

// 'add_endpoint' command.
void connection::cmd_add_endpoint(const boost::property_tree::ptree& root)
{
    
    std::string host;
    int port;
    std::string type;
    std::string transport;
    std::map<std::string, std::string> params;

    try {
	host = root.get<std::string>("host");
    } catch (...) {
	error(301, "host attribute is required");
	return;
    }

    try {
	std::istringstream buf(root.get<std::string>("port"));
	buf >> port;
    } catch (...) {
	error(301, "port attribute is required");
	return;
    }

    try {
	type = root.get<std::string>("type");
    } catch (...) {
	error(301, "type attribute is required");
	return;
    }

    try {
	transport = root.get<std::string>("transport");
    } catch (...) {
	// Transport defaults to tcp.
	transport = "tcp";
    }
    
    try {
	params["key"] = root.get<std::string>("key");
    } catch (...) {}
    
    try {
	params["certificate"] = root.get<std::string>("certificate");
    } catch (...) {}
    
    try {
	params["chain"] = root.get<std::string>("chain");
    } catch (...) {}
    
    try {
	d.add_endpoint(host, port, type, transport, params);
	ok(200, "Added endpoint.");
    } catch (...) {
	error(500, "Failed to add endpoint.");
    }

}

// 'remove_endpoint' command.
void connection::cmd_remove_endpoint(const boost::property_tree::ptree& root)
{

    std::string host;
    int port;
    std::string type;
    std::string transport;
    std::map<std::string, std::string> params;

    try {
	host = root.get<std::string>("host");
    } catch (...) {
	error(301, "host attribute is required");
	return;
    }

    try {
	std::istringstream buf(root.get<std::string>("port"));
	buf >> port;
    } catch (...) {
	error(301, "port attribute is required");
	return;
    }

    try {
	type = root.get<std::string>("type");
    } catch (...) {
	error(301, "type attribute is required");
	return;
    }

    try {
	transport = root.get<std::string>("transport");
    } catch (...) {
	// Transport defaults to tcp.
	transport = "tcp";
    }

    try {
	params["key"] = root.get<std::string>("key");
    } catch (...) {}
    
    try {
	params["certificate"] = root.get<std::string>("certificate");
    } catch (...) {}
    
    try {
	params["chain"] = root.get<std::string>("chain");
    } catch (...) {}
        
    try {
	d.remove_endpoint(host, port, type, transport, params);
	ok(200, "Removed endpoint.");
    } catch (...) {
	error(500, "Failed to remove endpoint.");
    }
        
}

// 'add_endpoint' command.
void connection::cmd_add_parameter(const boost::property_tree::ptree& root)
{

    std::string key;
    try {
	key = root.get<std::string>("key");
    } catch (...) {
	error(301, "key attribute is required");
	return;
    }
    
    std::string value;
    try {
	value = root.get<std::string>("value");
    } catch (...) {
	error(301, "value attribute is required");
	return;
    }
    
    try {
	d.add_parameter(key, value);
	ok(200, "Added parameter.");
    } catch (...) {
	error(500, "Failed to add parameter.");
    }

}

// 'add_endpoint' command.
void connection::cmd_remove_parameter(const boost::property_tree::ptree& root)
{

    std::string key;
    try {
	key = root.get<std::string>("key");
    } catch (...) {
	error(301, "key attribute is required");
	return;
    }
    
    try {
	d.remove_parameter(key);
	ok(200, "Removed parameter.");
    } catch (...) {
	error(500, "Failed to remove parameter.");
    }

}

// 'auth' command.
void connection::cmd_auth(const boost::property_tree::ptree& root)
{
    try {
	std::string username = root.get<std::string>("username");
	std::string password = root.get<std::string>("password");

	if (username == sp.username && password == sp.password) {
	    auth = true;
	    ok(200, "Authenticated.");
	    return;
	}

    } catch (...) {
    }
	
    error(331, "Authentication failure.");

}

// 'help' command.
void connection::cmd_help()
{

    /*
    std::ostringstream buf;

    buf << "Commands:\n"
	<< "\n"
	<< "  auth <user> <password>\n"
	<< "\n"
	<< "  help\n"
	<< "\n"
	<< "  add_interface <iface> <delay> [<filter>]\n"
	<< "      Starts packet capture from an interface.\n"
	<< "\n"
	<< "  remove_interface <iface> <delay> [<filter>]\n"
	<< "      Removes a previously enabled packet capture.\n"
	<< "\n"
	<< "  interfaces\n"
	<< "      Lists all interfaces, output is format iface:delay:filter\n"
	<< "\n"
	<< "  add_endpoint <host> <port> <type>\n"
	<< "      Adds an endpoint to delivery data to.\n"
	<< "      where type is one of: etsi nhis1.1\n"
	<< "\n"
	<< "  remove_endpoint <host> <port> <type>\n"
	<< "      Removes a previously enabled endpoint.\n"
	<< "      where type is one of: etsi nhis1.1\n"
	<< "\n"
	<< "  endpoints\n"
	<< "      Lists endpoints, format is host:port:type:description\n"
	<< "\n"
	<< "  add_target <liid> <class> <address>\n"
	<< "      Adds a new targeted IP address.\n"
	<< "      where class is one of: ipv4 ipv6\n"
	<< "\n"
	<< "  remove_target <class> <address>\n"
	<< "      Removes a previously targeted IP address.\n"
	<< "      where class is one of: ipv4 ipv6\n"
	<< "\n"
	<< "  targets\n"
	<< "      Lists targets, format is liid:class:address\n"
	<< "\n"
	<< "  add_parameter <key> <val>\n"
	<< "      Adds a new parameter, or changes a parameter value.\n"
	<< "\n"
	<< "  remove_parameter <key>\n"
	<< "      Removes a parameter value.\n"
	<< "\n"
	<< "  parameters\n"
	<< "      Lists parameters, format is key:value\n"
	<< "\n";
    */

    pt::ptree help;
    response(201, "Help information not available.", help);
}

// ETSI LI connection body, handles a single connection.
void connection::run()
{

    try {

	while (running) {

	    std::string line;

	    try {

		// Keep checking the loop condition if we're idle.
		bool activ = s->poll(1.0);
		if (!activ) continue;

		// Get the next command.
		try {
		    s->readline(line);
		} catch (...) {
		    // Socket close, probably.
		    break;
		}

		std::cerr << "Command: " << line << std::endl;

		// Create a root
		pt::ptree root;

		std::istringstream buf(line);

		try {
		    // Load the json file in this ptree
		    pt::read_json(buf, root);
		} catch (...) {
		    error(302, "Cannot parse command.");
		    continue;
		}

		std::string command;
		try {
		    command = root.get<std::string>("command");
		} catch (...) {
		    error(302, "The command attribute is missing.");
		    continue;
		}

		if (command == "help") {
		    cmd_help();
		    continue;
		}
		
		if (command == "auth") {
		    cmd_auth(root);
		    continue;
		}
		
		if (command == "quit") {
		    ok(200, "Tra, then.");
		    break;
		}

		// This is the authentication gate.  Can only do 'help' and
		// 'auth' until we've authenticated.
		if (!auth) {
		    error(330, "Authenticate before continuing.");
		    continue;
		}

		if (command == "endpoints") {
		    cmd_endpoints();
		    continue;
		} 
  
		if (command == "targets") {
		    cmd_targets();
		    continue;
		} 

		if (command == "interfaces") {
		    cmd_interfaces();
		    continue;
		}
  
		if (command == "parameters") {
		    cmd_parameters();
		    continue;
		}

		
		if (command == "add-interface") {
		    cmd_add_interface(root);
		    continue;
		} 

#ifdef ALDJALSKD

		if (lst.front() == "remove_interface") {
		    cmd_remove_interface(lst);
		    continue;
		} 

		if (lst.front() == "add_target") {
		    cmd_add_target(lst);
		    continue;
		} 

		if (lst.front() == "remove_target") {
		    cmd_remove_target(lst);
		    continue;
		} 

		if (lst.front() == "add_endpoint") {
		    cmd_add_endpoint(lst);
		    continue;
		} 

		if (lst.front() == "remove_endpoint") {
		    cmd_remove_endpoint(lst);
		    continue;
		} 

		if (lst.front() == "add_parameter") {
		    cmd_add_parameter(lst);
		    continue;
		} 

		if (lst.front() == "remove_parameter") {
		    cmd_remove_parameter(lst);
		    continue;
		} 
#endif
		error(301, "Command not known.");

	    } catch (...) {
		break;
	    }

	}

    } catch (std::exception& e) {
	std::cerr << e.what() << std::endl;
    }

    // Close the connection.
    s->close();

    // Add me to the tidy-up-list.
    svc.close_me(this);

}

