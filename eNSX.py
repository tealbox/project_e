import click
from nsxtSP import *
##@click.group()
##@click.pass_context
##def cli(ctx):
##    ctx.obj = sdwan.mySDWAN()

@click.command()
@click.option("--nsxhostname",  '-n', prompt="AVI IP", default='10.10.20.90', required=True)
@click.option("--username", '-u', prompt="NSX Username", default='admin', required=True)
@click.option("--password", '-p', prompt="NSX Password", hide_input=True, required=True)
def cli(avihostname, username, password):
    nsxMain(nsxhostname, username,password)

if __name__ == "__main__":
    cli()