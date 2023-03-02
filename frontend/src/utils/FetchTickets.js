import axios from "axios";
import UpdateTicketCounts from "../utils/UpdateTicketsCounts"

const BASE_URL = process.env.REACT_APP_SERVER_URL



const FetchTickets = async (localStorage) => {
    let result = {}
    try{
        result = await axios.get(BASE_URL + '/crm/api/tickets/',
        {
            headers: {
                'x-access-token': localStorage.getItem('token')
            }
        },{
          'userId' : localStorage.getItem('userId')
        })
        if (result.status === 200)return result.data
    }catch(error){
        console.log(error)
    }
    return result
}

export default FetchTickets