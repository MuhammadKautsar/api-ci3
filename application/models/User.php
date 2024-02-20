<?php

class User extends CI_Model
{
    public function save()
    {
        $data = [
            'email' => $this->input->post('email'),
            'password' => password_hash($this->input->post('password'), PASSWORD_DEFAULT),
        ];

        if ($this->db->insert('users', $data)) {
            return [
                'id' => $this->db->insert_id(),
                'success' => true,
                'message' => 'data berhasil dimasukkan'
            ];
        }
    }

    public function get($key = null, $value = null)
    {
        if($key != null) {
            $query = $this->db->get_where('users', array($key => $value));
            return $query->row();
        }

        $query = $this->db->get('users');
        return $query->result();
    }

    public function is_valid()
    {
        $email = $this->input->post('email');
        $password = $this->input->post('password');

        $hash = $this->get('email', $email)->password;

        if(password_verify($password, $hash)){
            return true;
        }

        return false;
    }

    public function delete($id)
    {
        $this->db->where('id', $id);
        if ($this->db->delete('users')) {
            return [
                'success' => true,
                'message' => 'data berhasil dihapus'
            ];
        }
    }

    public function update($id, $data)
    {
        $data = ['email' => $data->email];

        $this->db->where('id', $id);
        if ($this->db->update('users', $data)) {
            return [
                'success' => true,
                'message' => 'data berhasil diupdate'
            ];
        }
    }
}