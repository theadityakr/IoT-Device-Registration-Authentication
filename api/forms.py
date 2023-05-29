from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField,FileField
from wtforms.validators import InputRequired


class peerForm(FlaskForm):
    peer_address = StringField('Peer Address', validators=[InputRequired()])
    sender_address = StringField('Sender Address', validators=[InputRequired()])
    submit = SubmitField('Add Peer Node')

class taForm(FlaskForm):
    TA_address = StringField('TA Node Address', validators=[InputRequired()])
    sender_address = StringField('Sender Address', validators=[InputRequired()])
    submit = SubmitField('Add TA Node')

class registrationForm(FlaskForm):
    device_id = StringField('Device ID',validators=[InputRequired()])
    owner = StringField('Owner Address',validators=[InputRequired()])
    chal_file_dir = FileField('Challenge File',validators=[InputRequired()])
    resp_file_dir = FileField('Response File',validators=[InputRequired()])
    sender_address = StringField('Sender Address', validators=[InputRequired()])
    submit = SubmitField('Register IoT Device')

class authenticationForm(FlaskForm):
    device_id = StringField('Device ID', validators=[InputRequired()])
    count = StringField('Count of CRP to Authenticate', validators=[InputRequired()])
    resp = StringField('Response', validators=[InputRequired()])
    submit = SubmitField('Authenticate IoT Device')

class transferOwnerForm(FlaskForm):
    device_id = StringField('Device ID', validators=[InputRequired()])
    owner = StringField('Owner Address', validators=[InputRequired()])
    sender_address = StringField('Sender Address', validators=[InputRequired()])
    submit = SubmitField('Transfer Device Owner')

class checkOwnerForm(FlaskForm):
    device_id = StringField('Device ID', validators=[InputRequired()])
    submit = SubmitField('Check Current Device Owner')