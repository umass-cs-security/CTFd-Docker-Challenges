from CTFd.models import (
    db,
    Challenges,
)

# from flask_wtf import FlaskForm
from wtforms import (
    FileField,
    HiddenField,
    RadioField,
    StringField,
    SelectMultipleField,
)

from CTFd.forms import BaseForm
from CTFd.forms.fields import SubmitField


class DockerConfig(db.Model):
    """
    Docker Config Model. This model stores the config for docker API connections.
    """

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column("hostname", db.String(64), index=True) # will try to translated into real ip if "localhost" is specified
    enginename = db.Column("enginename", db.String(64), index=True) # will try to translated into real ip if "localhost" is specified
    tls_enabled = db.Column("tls_enabled", db.Boolean, default=False, index=True)
    ca_cert = db.Column("ca_cert", db.String(2200), index=True)
    client_cert = db.Column("client_cert", db.String(2000), index=True)
    client_key = db.Column("client_key", db.String(3300), index=True)
    repositories = db.Column("repositories", db.String(1024), index=True)


class DockerChallengeTracker(db.Model):
    """
    Docker Container Tracker. This model stores the users/teams active docker containers.
    """

    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE")
    )
    team_id = db.Column("team_id", db.String(64), index=True)
    user_id = db.Column("user_id", db.String(64), index=True)
    docker_image = db.Column("docker_image", db.String(64), index=True)
    container_flag = db.Column("container_flag", db.String(64), index=True)
    timestamp = db.Column("timestamp", db.Integer, index=True)
    revert_time = db.Column("revert_time", db.Integer, index=True)
    instance_id = db.Column("instance_id", db.String(128), index=True)
    ports = db.Column("ports", db.String(128), index=True)
    host = db.Column("host", db.String(128), index=True)


class DockerConfigForm(BaseForm):
    id = HiddenField()
    hostname = StringField(
        "Docker Hostname",
        description="The Hostname/IP and Port of your Docker Registry Server",
    )
    enginename = StringField(
        "Docker Enginename",
        description="The Hostname/IP and Port of your Docker Engine Server",
    )
    tls_enabled = RadioField("TLS Enabled?")
    ca_cert = FileField("CA Cert")
    client_cert = FileField("Client Cert")
    client_key = FileField("Client Key")
    repositories = SelectMultipleField("Repositories")
    submit = SubmitField("Submit")


class DockerImportForm(BaseForm):
    id = HiddenField()
    file = FileField(
        "File",
        description="Meta YAML file for importing the challenge from config file",
    )
    submit = SubmitField("Submit")


class DockerChallenge(Challenges):
    __mapper_args__ = {"polymorphic_identity": "docker"}
    id = db.Column(None, db.ForeignKey("challenges.id"), primary_key=True)
    # in format {docker registry host}:{docker registry port}/{image name} (no tag)
    docker_image = db.Column(db.String(128), index=True)
