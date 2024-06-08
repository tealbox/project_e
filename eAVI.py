import click
from myAVIAPI import *
##@click.group()
##@click.pass_context
##def cli(ctx):
##    ctx.obj = sdwan.mySDWAN()

@click.command()
@click.option("--avihostname",  '-v', prompt="AVI IP", default='10.10.20.90', required=True)
@click.option("--username", '-u', prompt="AVI Username", default='admin', required=True)
@click.option("--password", '-p', prompt="Password", hide_input=True, required=True)
def cli(avihostname, username, password):
    splistfile = f"{avihostname}_splist_{filetime}.pickle"
    spgrpsFile = f"{avihostname}_spgrps_{filetime}.txt"
    sprulesFile = f"{avihostname}_rules_{filetime}.txt"

    avi47 = myAVI(avihostname,username = username, password = password)
    avi47.login()

    vss = avi47.getVirtualService()
##    print (vss)
    for vs in vss:
        # print( rulePrint(vs, ['name','type','traffic_enabled', 'enabled' 'pool_ref']))
        pool_ref = vs.get('pool_ref',"No_POOL")
        if pool_ref != "No_POOL":
            pool_ref = pool_ref.split(sep="/")[-1]
            api = f"/pool-inventory/{pool_ref}/?include_name=true&include=health_score%2Cruntime%2Calert%2Cfaults&step=300&limit=72&"
            res = avi47.getAPI(api=api)
            if "runtime" in res:
                if "oper_status" in res["runtime"]:
                    if "state" in res["runtime"]["oper_status"]:
                        state = res["runtime"]["oper_status"]["state"]
                    else:
                        state = None
                    if "reason" in res["runtime"]["oper_status"]:
                        reason = res["runtime"]["oper_status"]["reason"]
                    else:
                        reason = None
                    if "last_changed_time" in res["runtime"]["oper_status"]:
                        secs = secs = res["runtime"]["oper_status"]["last_changed_time"]["secs"]
                    else:
                        sec = None
            else:
                state = None
                reason = None
                secs = None

        print( f'{vs["name"]}#{vs["type"]}#{vs["traffic_enabled"]}#{vs["enabled"]}#{pool_ref}', end="")
        print(f'#{state}#{reason}#{secs}')

    avi47.logout()


if __name__ == "__main__":
    cli()