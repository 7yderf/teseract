<?php
require './vendor/autoload.php';

    use PHPMailer\PHPMailer\PHPMailer;
    use PHPMailer\PHPMailer\SMTP;
    use PHPMailer\PHPMailer\Exception;

  
  function sendContactEmail($name, $email, $input){
   
    
    $mail = new PHPMailer(true);
    $mail->CharSet = "UTF-8";
   $mail->Encoding = 'base64';
   
    
    try {
          //Server settings
          $mail->SMTPDebug = SMTP::DEBUG_SERVER;                    //Enable verbose debug output
          $mail->isSMTP();                                            //Send using SMTP
          $mail->Host       = 'smtp.gmail.com';                     //Set the SMTP server to send through
          $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
          $mail->Username   = 'fredy.nazario@turn.com.mx';                     //SMTP username
          $mail->Password   = 'ingraviT0';                               //SMTP password
          $mail->SMTPSecure = 'tls';            //Enable implicit TLS encryption
          $mail->Port       = 587;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`
      
          //Recipients
          $mail->setFrom('fredy.nazario@turn.com.mx');
          $mail->addAddress('fredy.nazario@turn.com.mx');     //Add a recipient
          // $mail->addAddress('direccion@exsin.mx');     //Add a recipient
          // $mail->addAddress('contacto@exsin.mx');     //Add a recipient
         
      
          //Content
          $bodyContent = '
            <table style="max-width: 1200px; padding: 100px; margin:0 auto; border-collapse: collapse;" width="50%">
            <tr>
              <td style="padding: 8px 16px; background-color: #1b4bec">
                <img style="width: 200px; padding: 0; display: block; height: auto;"
                  src="https://www.grupotorresinmobiliario.com/_nuxt/logo_grupo_torres_blnk.7578f430.png">
              </td>
            </tr>
           
            <tr>
              <td style="background-color: #1b4bec">
                <div style="color: white; margin: 4% 10% 1%; text-align: center;font-family: sans-serif">
                  <h1 style="margin: .25em 0; padding: 0;">Se ha reaizado una petición de contacto</h1>
                  <h3>No dejes pasar tiempo... responde ahora</h3>
                </div>
              </td>
            </tr>
           
            <tr>
              <td style="background-color: #FFF; padding: 1em 3em;">
                <h1 style="margin: .25em 0; padding: 0;">Informacion de Contacto:</h1>
                <div style="color: #1b4bec; margin-bottom: 24px; text-align: justify;font-family: sans-serif; font-size: 16px; line-height: 30px; margin-top: 16px;">
                  
                     
                      <b>Nombre: </b>' . $input['first_name'] . ' ' . $input['last_name'] . 
                      '<br><b>Correo: </b>' . $input['email'] . 
                      '<br><b>Teléfono: </b>' . $input['telephone'] . '<br>';

          if(isset($input['Url'])){
              $bodyContent .= '<b>Propiedad de interés: </b>' . $input['Url'] . '<br>';
          }  
                  
                  
            $bodyContent .= '</div>
              </td>
            </tr>
  
            <tr>
              <td style="background-color: #626262; height: 1.5em;"></td>
            </tr>
  
            <tr>
              <td style="height: 4em;  background-color: #1b4bec; padding: 0 16px">
                <p style="color: white"> © 2024 Grupo Torres. Todos los derechos reservados.</p>
              </td>
            </tr>
          </table>
        '; 
          $mail->isHTML(true);                                  //Set email format to HTML
          $mail->Subject = 'Contacto desde web';
          $mail->Body    =  $bodyContent;
          
        
          $mail->send();
          return true;
      } catch (Exception $e) {
          $response['message'] = "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
          echo json_encode($response);
      }  
  } 




